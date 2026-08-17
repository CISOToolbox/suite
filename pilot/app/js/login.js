// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/backend/login_pilot.js).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * Login page script — variante PILOT (page de login centrale de la suite).
 * Gère ?error= et ?redirect=, révèle les boutons OAuth configurés et
 * renvoie vers la cible après authentification.
 *
 * Compilé vers login_pilot.js ; le script de build le copie sous le nom
 * app/js/login.js pour le module pilot (cf. ts-build.sh).
 * Voir login.ts pour la note de factorisation.
 */
(function () {
    "use strict";
    /**
     * Post-login target, restricted to a same-site path.
     *
     * `?redirect=` is attacker-supplied: a crafted login link would otherwise
     * send the user to another site after signing in (open redirect), and
     * `javascript:` in `location.href` executes IN THIS ORIGIN — an XSS on the
     * login page, which is worse. The server already applies this rule to its
     * own redirects (`_sanitize_redirect` in pilot/src/routes/auth.py); this is
     * the same rule on the browser side, which had none.
     *
     * Accepts only "/path": rejects "//evil.com" (protocol-relative), "/\evil"
     * (backslash, which several parsers fold to "/"), anything carrying a
     * scheme, and any value not starting with a single slash.
     */
    function safeRedirect(raw) {
        var v = raw || "/";
        if (v.charAt(0) !== "/")
            return "/";
        if (v.charAt(1) === "/" || v.charAt(1) === "\\")
            return "/";
        if (v.indexOf("\\") >= 0 || v.indexOf("://") >= 0)
            return "/";
        return v;
    }
    var params = new URLSearchParams(window.location.search);
    var error = params.get("error");
    var redirectTo = safeRedirect(params.get("redirect"));
    if (error) {
        var el = document.getElementById("login-error");
        el.style.display = "block";
        var messages = {
            auth_failed: "Authentication failed. Please try again.",
            userinfo_failed: "Could not retrieve your profile.",
            pending: "Your account is awaiting approval by an administrator.",
        };
        el.textContent = messages[error] || "An error occurred.";
    }
    fetch("/auth/providers").then(function (r) { return r.json(); }).then(function (data) {
        if (!data.auth_enabled) {
            window.location.href = redirectTo;
            return;
        }
        // Append ?redirect= to all login buttons so Pilot redirects back after OIDC
        var suffix = "?redirect=" + encodeURIComponent(redirectTo);
        ["btn-entra", "btn-google", "btn-oidc"].forEach(function (id) {
            var btn = document.getElementById(id);
            if (btn)
                btn.href = btn.href + suffix;
        });
        if (data.entra)
            document.getElementById("btn-entra").style.display = "flex";
        if (data.google)
            document.getElementById("btn-google").style.display = "flex";
        if (data.oidc) {
            document.getElementById("btn-oidc").style.display = "flex";
            if (data.oidc_label)
                document.getElementById("btn-oidc-label").textContent = "Sign in with " + data.oidc_label;
        }
    }).catch(function () { window.location.href = redirectTo; });
    fetch("/auth/me", { credentials: "same-origin" }).then(function (r) {
        if (r.ok)
            window.location.href = redirectTo;
    });
})();
