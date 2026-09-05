_registerTranslations("fr", {
    "ai.error": "Erreur : {msg}",
    "ai.triage_title": "Assistant IA",
    "ai.context_label": "Contexte pour l'analyse (optionnel)",
    "ai.context_ph": "Ex : ce paramètre est déjà validé côté serveur ; l'entrée provient d'une source de confiance…",
    "ai.deep_label": "Analyse approfondie (récupère le code source)",
    "ai.deep_hint": "Récupère le fichier concerné au commit scanné pour analyser le code réel (flux de données, atteignabilité).",
    "ai.run": "Lancer l'analyse",
    "ai.fp_true": "Probable faux positif",
    "ai.fp_false": "Probable vrai positif",
    "ai.deep_used": "Analyse basée sur le code source",
    "ai.deep_skipped": "Analyse approfondie ignorée :",
    "ai.remediation": "Remédiation",
    "ai.references": "Références",
    "ai.deepnote.branch_tip": "code affiché au dernier commit de la branche (commit scanné indisponible)",
    "ai.deepnote.no_file": "aucun fichier source associé à ce finding",
    "ai.deepnote.no_repo": "aucun dépôt configuré pour cette application",
    "ai.deepnote.token": "le token du dépôt n'a pas pu être déchiffré",
    "ai.deepnote.path": "chemin de fichier invalide",
    "ai.deepnote.not_found": "fichier introuvable à ce chemin",
    "ai.deepnote.too_large": "fichier trop volumineux pour l'analyse",
    "ai.deepnote.fetch_failed": "impossible de récupérer le fichier depuis le dépôt",
    "ai.deepnote.setup": "échec de préparation du dépôt",
    "common.error": "Erreur",
    "fd.delete": "Supprimer",
    "fd.delete_confirm": "Supprimer ce finding ?",
    "fd.deleted": "Finding supprimé",
    "matrix.critical": "Critique",
    "matrix.extreme": "Extrême",
    "matrix.high": "Élevé",
    "matrix.low": "Faible",
    "matrix.moderate": "Modéré",
    "matrix.significant": "Significatif",
    "matrix.x": "Impact",
    "matrix.y": "Vraisemblance",
    "settings.title": "Réglages",
    "settings.language": "Langue",
    "settings.ai_section": "Assistant IA",
    "settings.ai_enable": "Activer l'assistant IA",
    "settings.save": "Enregistrer",
    "settings.saved": "Réglages enregistrés",
    "settings.ai_privacy_warning": "En activant l'assistant IA :\n\n1. PARTAGE DE DONNÉES — Les données de votre analyse (contexte, exigences, remédiations) seront envoyées au fournisseur IA sélectionné. Assurez-vous que votre politique de confidentialité et vos engagements contractuels autorisent ce partage.\n\n2. EXPOSITION DE LA CLÉ API — La clé API est transmise depuis votre navigateur. Elle est visible dans les outils de développement (DevTools) et peut être capturée par des extensions navigateur. Utilisez de préférence un navigateur sans extensions ou un profil dédié.\n\n3. RÉSEAU — Les échanges sont chiffrés (HTTPS) mais peuvent être journalisés par un proxy d'entreprise.\n\nVoulez-vous continuer ?",
    "menu_file": "Fichier",
    "menu.import_apps": "Importer applications",
    "menu.export_report": "Exporter rapport",
    "feature.coming_soon": "Fonctionnalité à venir",
    "nav.applications": "Applications",
    "nav.findings": "Findings",
    "nav.sbom": "SBOM",
    "nav.scans": "Scans",
    "nav.measures": "Plan d'action",
    "dashboard.title": "Tableau de bord AppSec",
    "dashboard.total_apps": "Applications",
    "dashboard.findings": "Findings actifs",
    "dashboard.critical": "Critiques",
    "dashboard.high": "Élevés",
    "dashboard.medium": "Moyens",
    "dashboard.low": "Faibles",
    "dashboard.recent_scans": "Scans récents",
    "dashboard.by_scanner": "Par scanner",
    "dashboard.by_app": "Par application",
    "apps.title": "Applications",
    "apps.add": "Ajouter une application",
    "apps.name": "Nom",
    "apps.description": "Description",
    "apps.repo_url": "URL du dépôt Git",
    "apps.repo_branch": "Branche",
    "apps.repo_token": "Token d'accès (PAT)",
    "apps.token_hint": "Le token est chiffré en base. Laissez vide pour ne pas modifier.",
    "apps.scan_paths": "Repertoires a scanner (monorepo)",
    "apps.scan_paths_hint": "Un chemin par ligne relatif a la racine du repo. Laisser vide pour scanner tout le repo.",
    "apps.scan_paths_invalid": "Chemin invalide : '..' n'est pas autorise (traversee de repertoire)",
    "apps.notification_emails": "Destinataires des notifications",
    "apps.notification_emails_hint": "Un email par ligne (20 max). Ils recevront l'alerte des nouveaux findings et le récap hebdomadaire. Liste vide = aucune notification.",
    "apps.notification_lang": "Langue des emails",
    "apps.notification_lang_hint": "Appliquée aux destinataires sans compte — un utilisateur de la suite reçoit dans la langue de ses préférences.",
    "apps.section_notifications": "Notifications",
    "apps.section_code": "Analyse du code source (SAST, dependances, secrets)",
    "apps.section_images": "Scan d'images Docker",
    "apps.image_scan_enabled": "Activer le scan d'images",
    "apps.docker_images": "Images Docker (une par ligne)",
    "apps.docker_images_hint": "Referencesd'images de registre (GHCR, Docker Hub, registre prive).",
    "apps.image_token": "Token registre d'images (PAT)",
    "apps.image_token_hint": "Token pour acceder aux images privees. Chiffre en base. Laisser vide pour les images publiques.",
    "apps.scan_freq": "Fréquence de scan (heures)",
    "apps.scanners": "Scanners activés",
    "apps.criticality": "Criticité",
    "apps.save": "Enregistrer",
    "apps.cancel": "Annuler",
    "apps.configure": "Configurer",
    "apps.delete": "Supprimer",
    "apps.scan_now": "Scanner maintenant",
    "apps.scan_all": "Scanner tout",
    "apps.search": "Filtrer les applications…",
    "apps.no_match": "Aucune application ne correspond à ce filtre.",
    "apps.view_cards": "Affichage en tuiles",
    "apps.view_table": "Affichage en tableau",
    "apps.col_name": "Application",
    "apps.col_criticality": "Criticité",
    "apps.col_findings": "Findings",
    "apps.col_scanners": "Scanners",
    "apps.scan_all_triggered": "Scan déclenché sur {n} applications",
    "apps.token_invalid": "Le token semble invalide (il ne doit pas contenir de / ou d'espaces). Vérifiez que vous avez saisi un Personal Access Token.",
    "apps.scan_triggered": "Scan déclenché",
    "apps.delete_confirm": "Supprimer cette application et tous ses findings ?",
    "apps.deleted": "Application supprimée",
    "apps.last_scan": "Dernier scan",
    "apps.never": "Jamais",
    "apps.no_apps": "Aucune application configurée",
    "findings.title": "Findings",
    // Rebuilt finding labels (type/scanner + evidence) — see ct_findings.js
    "finding.trivy_fs.title": "{cve} : {package}@{installed_version}",
    "finding.trivy_fs.desc": "Vulnérabilité {cve} affectant {package} {installed_version}.\n\n{original}",
    "finding.trivy_image.title": "{cve} : {package}@{installed_version} dans {image}",
    "finding.trivy_image.desc": "Vulnérabilité {cve} affectant {package} {installed_version} (image {image}).\n\n{original}",
    "finding.gitleaks.title": "Secret détecté : {rule} dans {file}",
    "finding.gitleaks.desc": "Une correspondance de la règle « {rule} » a été trouvée dans {file}:{line}.\n\n{original}",
    "finding.semgrep.title": "SAST : {rule_id}",
    "finding.semgrep.desc": "La règle SAST {rule_id} a été déclenchée dans {file}:{line}.\n\n{original}",
    "findings.all_apps": "Toutes les applications",
    "findings.search_app": "Rechercher une application…",
    "findings.all_severities": "Toutes les sévérités",
    "findings.all_scanners": "Tous les scanners",
    "findings.all_statuses": "Tous les statuts",
    "findings.search": "Rechercher (titre, cible, CVE)...",
    "findings.triage": "Trier",
    "findings.status_new": "Nouveau",
    "findings.status_to_fix": "À corriger",
    "findings.status_false_positive": "Faux positif",
    "findings.fp_bulk_title": "Marquer en faux positif",
    "findings.fp_bulk_label": "Justification (obligatoire)",
    "findings.fp_bulk_placeholder": "Pourquoi ces findings sont-ils des faux positifs ? Ex : composant non exposé, mitigation existante, vulnérabilité non exploitable…",
    "findings.fp_bulk_required": "La justification est obligatoire",
    "findings.status_fixed": "Corrigé",
    "findings.status_pending": "En attente",
    "findings.status_running": "En cours",
    "findings.status_completed": "Terminé",
    "findings.status_failed": "Échoué",
    "findings.status_skipped": "Ignoré",
    "scans.status_pending": "En attente",
    "scans.status_running": "En cours",
    "scans.status_completed": "Terminé",
    "scans.status_failed": "Échoué",
    "scans.status_skipped": "Ignoré",
    "findings.selected": "finding(s) sélectionné(s)",
    "findings.selected_n": "{n} finding(s) sélectionné(s)",
    "findings.col_title": "Titre",
    "findings.choose_action": "Choisir une action",
    "findings.clear_selection": "Annuler",
    "findings.no_findings": "Aucun finding",
    "findings.filter_severity": "Severite",
    "findings.filter_status": "Statut",
    "findings.filter_scanner": "Scanner",
    "findings.filter_patch": "Patch",
    "findings.target": "Cible",
    "findings.col_patch": "Patch",
    "findings.all_patches": "Tous patches",
    "findings.patch_available": "Patch disponible",
    "findings.patch_unavailable": "Sans patch",
    "findings.patch_none": "Aucun patch",
    "findings.patch_status": "Patch editeur",
    "findings.installed_version": "Version installee",
    "dashboard.cve_patchable": "CVE patchables",
    "findings.evidence": "Preuves",
    "findings.ai_assist": "Assistant IA",
    "findings.first_seen": "Première détection :",
    "findings.last_seen": "Dernière détection :",
    "findings.back": "Retour",
    "sbom.title": "Software Bill of Materials",
    "sbom.all_ecosystems": "Tous les écosystèmes",
    "sbom.search": "Rechercher un package...",
    "sbom.export_csv": "Exporter CSV",
    "sbom.package": "Package",
    "sbom.version": "Version",
    "sbom.ecosystem": "Écosystème",
    "sbom.license": "Licence",
    "sbom.direct": "Direct",
    "sbom.vulnerable": "Vulnérable",
    "sbom.parent": "Dépendance parente",
    "sbom.transitive": "transitif",
    "sbom.no_entries": "Aucune entrée SBOM",
    "sbom.vulnerable_only": "Vulnérables uniquement",
    "scans.title": "Historique des scans",
    "scans.scanner": "Scanner",
    "scans.status": "Statut",
    "measures.status_a_faire": "À faire",
    "measures.status_en_cours": "En cours",
    "measures.status_termine": "Terminé",
    "scans.findings_count": "Findings",
    "scans.duration": "Durée",
    "scans.triggered_by": "Déclenché par",
    "scans.reset_stuck": "Débloquer",
    "scans.reset_stuck_tip": "Forcer en échec tous les scans bloqués (running/pending) de cette application. Admin uniquement.",
    "scans.reset_confirm": "Débloquer tous les scans en cours/attente pour « {name} » ? Ils seront marqués en échec.",
    "scans.reset_done": "{count} scan(s) débloqué(s).",
    "error.bad_request": "Requête invalide",
    "error.forbidden": "Accès refusé",
    "error.not_found": "Ressource introuvable",
    "error.conflict": "Conflit de données",
    "error.validation": "Données invalides",
    "error.server": "Erreur serveur, veuillez réessayer",
    "error.generic": "Une erreur est survenue",
    "scanner.trivy_fs": "Dépendances",
    "scanner.trivy_image": "Images Docker",
    "scanner.gitleaks": "Secrets",
    "scanner.semgrep": "SAST",
    "nav.ignore_rules": "Regles d'exclusion",
    "ignore.title": "Regles d'exclusion",
    "ignore.add": "Ajouter une regle",
    "ignore.help": "Les regles d'exclusion auto-trient les findings en faux positif a chaque scan. Chaque regle a une justification obligatoire et est tracee dans l'audit log.",
    "ignore.empty": "Aucune regle configuree.",
    "ignore.col_scope": "Perimetre",
    "ignore.col_reason": "Justification",
    "ignore.col_by": "Par",
    "ignore.all_apps": "Toutes les applications",
    "ignore.type.cve_id": "CVE ID",
    "ignore.type.package": "Package",
    "ignore.type.scanner_rule": "Regle scanner",
    "ignore.type.target_pattern": "Pattern cible",
    "ignore.type.severity": "Severite",
    "ignore.type.ecosystem": "Ecosysteme",
    "ignore.created": "Regle creee",
    "ignore.updated": "Regle mise a jour",
    "ignore.edit": "Modifier la regle",
    "ignore.deleted": "Regle supprimee",
    "ignore.confirm_delete": "Supprimer cette regle ?",
    "ignore.err_required": "Justification obligatoire",
    "ignore.err_no_criteria": "Au moins un critere requis",
    "ignore.col_criteria": "Criteres",
    "ignore.add_criterion": "Ajouter un critere (AND)",
    "ignore.search_apps": "Filtrer les applications...",
    "ignore.reason_placeholder": "Faux positif confirme / Risque accepte / Non applicable...",
    "ignore.offer_title": "Creer une regle d'exclusion ?",
    "ignore.offer_body": "Ce finding a ete declare faux positif. Souhaitez-vous creer une regle pour ignorer automatiquement les findings similaires lors des prochains scans ?",
    "ignore.offer_yes": "Creer la regle",
    "ignore.offer_no": "Non merci",
    "nav.audit": "Journal d'audit",
    "audit.title": "Journal d'audit",
    "audit.retention": "Retention",
    "audit.apply": "Appliquer",
    "audit.days": "jours",
    "audit.search": "Rechercher...",
    "audit.empty": "Aucune entree dans le journal",
    "audit.entries": "entrees",
    "audit.col_date": "Date",
    "audit.col_user": "Utilisateur",
    "audit.col_action": "Action",
    "audit.col_target": "Cible",
    "audit.col_details": "Details",
    "audit.action.app.create": "Creation d'application",
    "audit.action.app.update": "Modification d'application",
    "audit.action.app.delete": "Suppression d'application",
    "audit.action.scan.trigger": "Lancement de scan",
    "audit.action.finding.triage": "Triage de finding",
    "audit.action.finding.bulk_triage": "Triage en masse",
    "audit.action.ignore_rule.create": "Creation de regle d'exclusion",
    "audit.action.ignore_rule.update": "Modification de regle d'exclusion",
    "audit.action.ignore_rule.delete": "Suppression de regle d'exclusion",
    "nav.aide": "AIDE",
    "nav.methodo": "Methodologie",
    "nav.usage": "Utilisation",
    "help.tab_methodo": "Méthodologie AppSec",
    "help.tab_usage": "Guide d'utilisation",
    "help.methodo_html": "<h1 class=\"heading-blue\">AppSec (SAST/SCA) — Méthodologie</h1>"
        + "<p class=\"text-muted\">Détection continue des vulnérabilités applicatives : dépendances (SCA), code source (SAST), secrets et images de conteneurs.</p>"
        + "<h2>1. Approche shift-left</h2>"
        + "<p>Le module applique le principe du <strong>shift-left</strong> : détecter les vulnérabilités le plus tôt possible dans le cycle de développement, là où leur correction coûte le moins cher. Les dépôts de code et les images publiées sont analysés en continu, sans attendre un audit ponctuel.</p>"
        + "<h2>2. Les quatre familles d'analyse</h2>"
        + "<table><tr><th>Famille</th><th>Moteur</th><th>Ce qui est détecté</th></tr>"
        + "<tr><td>SCA (dépendances)</td><td>Trivy FS</td><td>CVE connues dans les dépendances déclarées (<code>requirements.txt</code>, <code>package.json</code>, <code>go.sum</code>, <code>Gemfile.lock</code>…)</td></tr>"
        + "<tr><td>Images de conteneurs</td><td>Trivy Image</td><td>CVE des paquets système (apt, apk) et des dépendances embarquées dans les couches d'image</td></tr>"
        + "<tr><td>Secrets</td><td>Gitleaks</td><td>Clés API, tokens, mots de passe et certificats commités, y compris dans l'historique Git</td></tr>"
        + "<tr><td>SAST (code source)</td><td>Semgrep</td><td>Vulnérabilités dans le code : injections SQL, XSS, désérialisation non sécurisée, SSRF…</td></tr></table>"
        + "<h3>SCA — analyse de composition logicielle</h3>"
        + "<p>Chaque CVE remonte le package concerné, la version installée et, quand elle existe, la <em>version corrigée</em> publiée par l'éditeur. Cette information fonde la doctrine des <strong>quick wins</strong> : une CVE avec patch se corrige par une simple montée de version.</p>"
        + "<ul><li>Maintenir les dépendances à jour (Renovate, Dependabot)</li>"
        + "<li>Corriger en priorité les CVE disposant d'un patch éditeur</li>"
        + "<li>Évaluer le risque réel des CVE sans patch (exposition, WAF, désactivation de la fonctionnalité)</li></ul>"
        + "<h3>Images de conteneurs</h3>"
        + "<p>L'analyse porte sur les couches de l'image publiée, pas sur le code source : elle est complémentaire de la SCA qui scanne le code avant le build. Une image peut être vulnérable alors que le code ne l'est pas (paquets système obsolètes de l'image de base).</p>"
        + "<ul><li>Utiliser des images de base minimales (<code>-slim</code>, <code>-alpine</code>, distroless)</li>"
        + "<li>Reconstruire régulièrement pour intégrer les correctifs de l'image de base</li></ul>"
        + "<h3>Détection de secrets</h3>"
        + "<div class=\"ct-help-tip\"><strong>Doctrine :</strong> un secret présent dans l'historique Git est considéré comme compromis, même supprimé dans un commit ultérieur. La seule remédiation valable est la <strong>rotation</strong> du secret ; l'effacer du code ne suffit pas.</div>"
        + "<ul><li>Externaliser les secrets (fichiers <code>.env</code> gitignorés, gestionnaire de secrets type Vault)</li>"
        + "<li>Bloquer les commits contenant des secrets via un hook pre-commit</li></ul>"
        + "<h3>SAST — analyse statique du code</h3>"
        + "<p>Semgrep applique des règles déclaratives issues des rulesets <strong>OWASP Top 10</strong>, default et spécifiques aux langages (Python, JavaScript, TypeScript). Le SAST produit structurellement plus de faux positifs que la SCA : un triage rapide et justifié est indispensable pour maintenir la confiance dans l'outil.</p>"
        + "<h2>3. Modèle de sévérité</h2>"
        + "<p>Les findings sont classés sur l'échelle harmonisée de la suite, dérivée du score CVSS :</p>"
        + "<table><tr><th>Niveau</th><th>CVSS indicatif</th><th>Traitement attendu</th></tr>"
        + "<tr><td><strong>Critique</strong></td><td>9.0 – 10.0</td><td>Correction immédiate, sans attendre le cycle de release</td></tr>"
        + "<tr><td><strong>Élevé</strong></td><td>7.0 – 8.9</td><td>Correction prioritaire, planifiée à court terme</td></tr>"
        + "<tr><td><strong>Moyen</strong></td><td>4.0 – 6.9</td><td>Correction planifiée dans le cycle normal</td></tr>"
        + "<tr><td><strong>Faible</strong></td><td>0.1 – 3.9</td><td>Correction opportuniste (lors d'une montée de version)</td></tr>"
        + "<tr><td><strong>Info</strong></td><td>—</td><td>Informatif, pas de risque direct</td></tr></table>"
        + "<p>La priorisation croise trois facteurs : la <strong>sévérité</strong> du finding, la <strong>criticité</strong> de l'application concernée et la <strong>disponibilité d'un patch éditeur</strong>. Une CVE élevée avec patch sur une application critique passe avant une CVE critique sans patch sur une application secondaire.</p>"
        + "<h2>4. Doctrine de triage et de remédiation</h2>"
        + "<p>Chaque finding suit un cycle de vie :</p>"
        + "<table><tr><th>Statut</th><th>Signification</th></tr>"
        + "<tr><td><strong>Nouveau</strong></td><td>Détecté, pas encore analysé par un humain</td></tr>"
        + "<tr><td><strong>À corriger</strong></td><td>Confirmé comme vulnérabilité réelle, en attente de remédiation</td></tr>"
        + "<tr><td><strong>Faux positif</strong></td><td>Détection incorrecte ou risque non applicable — justification obligatoire</td></tr>"
        + "<tr><td><strong>Corrigé</strong></td><td>Remédiation appliquée, à confirmer par un re-scan</td></tr></table>"
        + "<p>Principes :</p>"
        + "<ul><li>Tout finding confirmé donne lieu à une <strong>remédiation</strong> avec un responsable et une échéance — pas de vulnérabilité « connue mais sans pilote »</li>"
        + "<li>Tout classement en faux positif est <strong>justifié et tracé</strong> dans le journal d'audit</li>"
        + "<li>Les faux positifs récurrents sont industrialisés par des <strong>règles d'exclusion</strong> : un auto-classement justifié et audité, jamais une suppression silencieuse</li>"
        + "<li>Un statut « Corrigé » n'est acquis que si le finding ne réapparaît pas au scan suivant (déduplication entre scans)</li></ul>"
        + "<h2>5. SBOM et traçabilité</h2>"
        + "<p>Le <strong>SBOM</strong> (Software Bill of Materials) inventorie tous les composants logiciels, directs et transitifs, avec leurs versions et licences. C'est l'outil de réponse rapide aux vulnérabilités majeures : lors d'un « Log4Shell », il répond en quelques secondes à la question « où utilise-t-on ce composant ? ».</p>"
        + "<h2>6. Référentiels</h2>"
        + "<ul><li><strong>OWASP Top 10</strong> — socle des règles SAST et de la formation au code sécurisé</li>"
        + "<li><strong>CVE / NVD</strong> — référentiel public des vulnérabilités, source des identifiants et des liens de détail</li>"
        + "<li><strong>CVSS</strong> — système de score (0-10) dont dérive le modèle de sévérité ci-dessus</li></ul>"
        + "<h2>7. Glossaire</h2>"
        + "<table><tr><th>Terme</th><th>Définition</th></tr>"
        + "<tr><td>SCA</td><td>Software Composition Analysis — analyse des dépendances tierces</td></tr>"
        + "<tr><td>SAST</td><td>Static Application Security Testing — analyse statique du code source</td></tr>"
        + "<tr><td>SBOM</td><td>Software Bill of Materials — inventaire des composants logiciels</td></tr>"
        + "<tr><td>CVE</td><td>Common Vulnerabilities and Exposures — identifiant unique de vulnérabilité</td></tr>"
        + "<tr><td>CVSS</td><td>Common Vulnerability Scoring System — score de sévérité (0-10)</td></tr>"
        + "<tr><td>Shift-left</td><td>Intégrer la sécurité le plus tôt possible dans le cycle de développement</td></tr>"
        + "<tr><td>Dédup</td><td>Déduplication — rapprochement des findings identiques entre scans successifs</td></tr></table>"
        + "<h2>8. Intégration à la suite CISO Toolbox</h2>"
        + "<p>En déploiement suite, les <strong>remédiations</strong> de ce module remontent automatiquement dans le <strong>plan d'action de Pilot</strong> (hub de gouvernance), y sont consolidées avec les items des autres modules sous le terme commun <strong>Action</strong>, et peuvent être regroupées en <strong>projets</strong> pour piloter l'avancement transverse. Le module reste l'autorité de son domaine — Pilot ne fait que consolider.</p>",
    "help.usage_html": "<h1 class=\"heading-blue\">AppSec (SAST/SCA) — Guide d'utilisation</h1>\n\n<h2>Fonctionnalités nécessitant l'IA</h2>\n<p>Ces fonctionnalités appellent un modèle de langage et ne sont disponibles qu'une fois l'IA configurée. Elles sont <strong>optionnelles</strong> : sans configuration, elles sont masquées ou inactives et le reste du module fonctionne normalement.</p>\n<ul>\n<li><strong>Analyse IA d'un finding</strong> : recommandation de triage, avec une option d'<em>analyse approfondie</em> qui fournit davantage de contexte au modèle</li>\n</ul>\n<p class=\"ct-help-tip\">Où configurer : dans une installation autonome, via <strong>Réglages &rarr; IA</strong> du module (votre propre clé API). Dans la suite, les clés sont centralisées par <strong>Pilot</strong> et poussées aux modules &mdash; rien à saisir ici, et l'accès à l'IA se donne par utilisateur dans les habilitations.</p>"
        + "<p class=\"text-muted\">Pages, boutons et flux de travail du module. La navigation se fait par la barre latérale ; la barre d'application propose la langue (FR/EN), le thème clair/sombre et les réglages (assistant IA).</p>"
        + "<h2>1. Tableau de bord</h2>"
        + "<p>Tuiles : nombre d'applications, findings actifs par sévérité (Critique, Élevé, Moyen, Faible) et <strong>CVE patchables</strong> (nombre et pourcentage de CVE actives disposant d'un patch éditeur). Chaque tuile est cliquable et ouvre la liste filtrée correspondante. Le tableau <strong>Par application</strong> détaille les findings par sévérité (lignes cliquables) ; <strong>Scans récents</strong> affiche les 10 derniers scans.</p>"
        + "<h2>2. Applications</h2>"
        + "<p>Chaque application représente un périmètre de scan, affiché en carte (criticité, dernier scan, badges de sévérité, nombre de scanners). Boutons : <strong>Ajouter une application</strong>, <strong>Scanner tout</strong> ; sur chaque carte : lancer un scan (▶) ou <strong>Configurer</strong>. Cliquer sur la carte ouvre le détail : résumé de configuration et findings de l'application, filtrables (sévérité, statut, scanner, recherche).</p>"
        + "<p>Formulaire de configuration :</p>"
        + "<ul><li><strong>Nom, description, criticité, fréquence de scan</strong> (heures entre deux scans automatiques)</li>"
        + "<li><strong>Analyse du code source</strong> : URL du dépôt Git, branche (défaut <code>main</code>), token d'accès PAT pour dépôts privés (chiffré en base), <strong>Répertoires à scanner</strong> (monorepo — un chemin par ligne relatif à la racine, <code>..</code> interdit), cases Dépendances / Secrets / SAST</li>"
        + "<li><strong>Scan d'images Docker</strong> : case d'activation, liste d'images (une par ligne, GHCR / Docker Hub / registre privé), token registre pour images privées (chiffré en base)</li></ul>"
        + "<div class=\"ct-help-tip\"><strong>Attention :</strong> supprimer une application supprime aussi tous ses findings.</div>"
        + "<h2>3. Findings</h2>"
        + "<p>Liste de toutes les détections. Filtres en pills : <strong>sévérité</strong> (Critique, Élevé, Moyen, Faible, Info), <strong>statut</strong>, <strong>scanner</strong> (Dépendances, Images Docker, Secrets, SAST), <strong>patch</strong> (Avec patch / Sans patch) ; plus liste déroulante d'application et recherche textuelle (titre, cible, CVE).</p>"
        + "<div class=\"ct-help-tip\"><strong>Astuce :</strong> à l'ouverture, la liste est filtrée sur le statut <strong>Nouveau</strong>. Cliquez sur « Tous les statuts » pour voir aussi les findings déjà triés.</div>"
        + "<p><strong>Colonnes :</strong> sévérité, titre (+ CVE), cible, application, scanner, patch (badge vert avec la version corrigée, rouge « Sans patch »), statut.</p>"
        + "<p><strong>Détail d'un finding :</strong> cliquez sur une ligne — description, preuves (evidence), version installée / version corrigée, dates de première et dernière détection, remédiation liée éventuelle, boutons de triage et assistant IA.</p>"
        + "<p><strong>Triage en masse :</strong> cochez plusieurs lignes puis utilisez la barre d'actions en bas :</p>"
        + "<ul><li><strong>À corriger</strong> — ouvre le formulaire de remédiation : une seule remédiation couvre toute la sélection (titre, description, responsable via l'annuaire, échéance)</li>"
        + "<li><strong>Corrigé</strong> — marque la sélection comme remédiée</li>"
        + "<li><strong>Faux positif</strong> — justification obligatoire, puis proposition de créer une règle d'exclusion pré-remplie</li></ul>"
        + "<h2>4. Assistant IA</h2>"
        + "<p>À activer dans les <strong>réglages</strong> (icône de la barre d'application). Sur le détail d'un finding, le bouton d'analyse IA ouvre un formulaire : contexte optionnel pour l'analyste, et option <strong>analyse approfondie</strong> qui récupère le fichier source au commit scanné (nécessite un dépôt configuré). Le résultat indique probable vrai/faux positif avec un niveau de confiance, une recommandation de sévérité, un résumé, une remédiation et des références.</p>"
        + "<h2>5. SBOM</h2>"
        + "<p>Inventaire de tous les packages (directs et transitifs) détectés par les scans. Filtres : application, écosystème (liste dynamique : npm, pypi, go…), case <strong>Vulnérables uniquement</strong>, recherche par nom. Les dépendances transitives affichent leur <strong>dépendance parente</strong> (lien cliquable qui filtre la liste). Les badges CVE ouvrent la fiche NVD : rouge = CVE active, grisé = CVE triée (faux positif, corrigé). Bouton <strong>Exporter CSV</strong> en haut à droite (respecte le filtre application).</p>"
        + "<h2>6. Scans</h2>"
        + "<p>Historique de tous les scans : application, scanner, statut (En attente, En cours, Terminé, Échoué, Ignoré), nombre de findings, déclenché par, date et message d'erreur éventuel. Pour les admins, le bouton <strong>Débloquer</strong> force en échec les scans restés bloqués (en cours/en attente).</p>"
        + "<h2>7. Plan d'action</h2>"
        + "<p>Remédiations créées depuis les Findings (action « À corriger »). Colonnes : ID, titre, nombre de findings couverts, statut (À faire, En cours, Terminé), responsable, échéance. Cliquer sur une ligne ouvre la fiche : modification, journal d'avancement (notes horodatées), suppression. Sélection multiple : marquer <strong>Terminé</strong> ou <strong>Supprimer</strong> en masse.</p>"
        + "<h2>8. Règles d'exclusion (admin)</h2>"
        + "<p>Auto-triage des faux positifs récurrents. Une règle combine un ou plusieurs critères (logique AND) :</p>"
        + "<table><tr><th>Type</th><th>Description</th><th>Exemple</th></tr>"
        + "<tr><td><code>cve_id</code></td><td>CVE exacte</td><td><code>CVE-2024-1234</code></td></tr>"
        + "<tr><td><code>package</code></td><td>Nom de package (glob)</td><td><code>lodash</code>, <code>com.fasterxml.*</code></td></tr>"
        + "<tr><td><code>scanner_rule</code></td><td>ID de règle scanner</td><td><code>generic-api-key</code></td></tr>"
        + "<tr><td><code>target_pattern</code></td><td>Chemin ou cible (glob)</td><td><code>tests/*</code>, <code>*.test.js</code></td></tr>"
        + "<tr><td><code>severity</code></td><td>Sévérité exacte</td><td><code>low</code>, <code>info</code></td></tr>"
        + "<tr><td><code>ecosystem</code></td><td>Écosystème de package</td><td><code>npm</code>, <code>pypi</code></td></tr></table>"
        + "<p>Périmètre : toutes les applications ou une sélection (champ de recherche). Justification obligatoire. Chaque règle peut être activée/désactivée (ON/OFF), modifiée ou supprimée. À la création ou modification, les findings existants correspondants (Nouveau, À corriger) sont <strong>auto-triés rétroactivement</strong> en faux positif. Après un triage manuel en faux positif, le module propose de créer une règle pré-remplie avec les critères du finding.</p>"
        + "<h2>9. Journal d'audit (admin)</h2>"
        + "<p>Trace des actions du module : date, utilisateur, action, cible, détails, adresse IP. Recherche textuelle et durée de rétention configurable (en jours) en haut de page.</p>"
        + "<h2>10. Astuces</h2>"
        + "<table><tr><th>Action</th><th>Comment</th></tr>"
        + "<tr><td>Quick wins</td><td>Tableau de bord → tuile « CVE patchables » → liste des CVE avec patch éditeur</td></tr>"
        + "<tr><td>Triage rapide</td><td>Findings → cocher plusieurs lignes → barre d'actions en bas</td></tr>"
        + "<tr><td>Voir les findings déjà triés</td><td>Findings → pill « Tous les statuts »</td></tr>"
        + "<tr><td>Scanner une application</td><td>Applications → carte de l'app → « Scanner maintenant »</td></tr>"
        + "<tr><td>Scanner tout le parc</td><td>Applications → bouton « Scanner tout »</td></tr>"
        + "<tr><td>Exporter le SBOM</td><td>SBOM → bouton « Exporter CSV »</td></tr>"
        + "<tr><td>Retrouver qui utilise un package</td><td>SBOM → recherche par nom de package</td></tr></table>",
});
