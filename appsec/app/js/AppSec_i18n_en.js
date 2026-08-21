_registerTranslations("en", {
    "ai.error": "Error: {msg}",
    "ai.triage_title": "AI assistant",
    "ai.context_label": "Context for the analysis (optional)",
    "ai.context_ph": "e.g. this parameter is already validated server-side; input comes from a trusted source…",
    "ai.deep_label": "Deep analysis (fetch source code)",
    "ai.deep_hint": "Fetches the referenced file at the scanned commit to analyze the actual code (data flow, reachability).",
    "ai.run": "Run analysis",
    "ai.fp_true": "Probable false positive",
    "ai.fp_false": "Probable true positive",
    "ai.deep_used": "Analysis based on source code",
    "ai.deep_skipped": "Deep analysis skipped:",
    "ai.remediation": "Remediation",
    "ai.references": "References",
    "ai.deepnote.branch_tip": "code shown at the branch tip (scanned commit unavailable)",
    "ai.deepnote.no_file": "no source file associated with this finding",
    "ai.deepnote.no_repo": "no repository configured for this application",
    "ai.deepnote.token": "the repository token could not be decrypted",
    "ai.deepnote.path": "invalid file path",
    "ai.deepnote.not_found": "file not found at that path",
    "ai.deepnote.too_large": "file too large to analyze",
    "ai.deepnote.fetch_failed": "could not fetch the file from the repository",
    "ai.deepnote.setup": "repository setup failed",
    "common.error": "Error",
    "fd.delete": "Delete",
    "fd.delete_confirm": "Delete this finding?",
    "fd.deleted": "Finding deleted",
    "matrix.critical": "Critical",
    "matrix.extreme": "Extreme",
    "matrix.high": "High",
    "matrix.low": "Low",
    "matrix.moderate": "Moderate",
    "matrix.significant": "Significant",
    "matrix.x": "Impact",
    "matrix.y": "Likelihood",
    "settings.title": "Settings",
    "settings.language": "Language",
    "settings.ai_section": "AI Assistant",
    "settings.ai_enable": "Enable AI assistant",
    "settings.save": "Save",
    "settings.saved": "Settings saved",
    "settings.ai_privacy_warning": "By enabling the AI assistant:\n\n1. DATA SHARING — Your analysis data (context, requirements, controls) will be sent to the selected AI provider. Make sure your privacy policy and contractual obligations allow this.\n\n2. API KEY EXPOSURE — The API key is transmitted directly from your browser. It is visible in browser DevTools and can be captured by browser extensions. Use a browser without extensions or a dedicated profile.\n\n3. NETWORK — Communications are encrypted (HTTPS) but may be logged by corporate proxies.\n\nDo you want to continue?",
    "menu_file": "File",
    "menu.import_apps": "Import applications",
    "menu.export_report": "Export report",
    "feature.coming_soon": "Feature coming soon",
    "nav.applications": "Applications",
    "nav.findings": "Findings",
    "nav.sbom": "SBOM",
    "nav.scans": "Scans",
    "nav.measures": "Action Plan",
    "dashboard.title": "AppSec Dashboard",
    "dashboard.total_apps": "Applications",
    "dashboard.findings": "Active Findings",
    "dashboard.critical": "Critical",
    "dashboard.high": "High",
    "dashboard.medium": "Medium",
    "dashboard.low": "Low",
    "dashboard.recent_scans": "Recent Scans",
    "dashboard.by_scanner": "By Scanner",
    "dashboard.by_app": "By Application",
    "apps.title": "Applications",
    "apps.add": "Add Application",
    "apps.name": "Name",
    "apps.description": "Description",
    "apps.repo_url": "Git Repository URL",
    "apps.repo_branch": "Branch",
    "apps.repo_token": "Access Token (PAT)",
    "apps.token_hint": "Token is encrypted at rest. Leave blank to keep unchanged.",
    "apps.scan_paths": "Directories to scan (monorepo)",
    "apps.scan_paths_hint": "One path per line relative to the repo root. Leave empty to scan the entire repo.",
    "apps.scan_paths_invalid": "Invalid path: '..' is not allowed (path traversal)",
    "apps.notification_emails": "Notification recipients",
    "apps.notification_emails_hint": "One email per line (max 20). They receive the new-findings alert and the weekly recap. Empty list = no notifications.",
    "apps.notification_lang": "Email language",
    "apps.notification_lang_hint": "Applied to recipients without an account — suite users receive in their preferred language.",
    "apps.section_notifications": "Notifications",
    "apps.section_code": "Source code analysis (SAST, dependencies, secrets)",
    "apps.section_images": "Docker image scanning",
    "apps.image_scan_enabled": "Enable image scanning",
    "apps.docker_images": "Docker Images (one per line)",
    "apps.docker_images_hint": "Registry image references (GHCR, Docker Hub, private registry).",
    "apps.image_token": "Image registry token (PAT)",
    "apps.image_token_hint": "Token to access private images. Encrypted at rest. Leave empty for public images.",
    "apps.scan_freq": "Scan Frequency (hours)",
    "apps.scanners": "Enabled Scanners",
    "apps.criticality": "Criticality",
    "apps.save": "Save",
    "apps.cancel": "Cancel",
    "apps.configure": "Configure",
    "apps.delete": "Delete",
    "apps.scan_now": "Scan Now",
    "apps.scan_all": "Scan All",
    "apps.search": "Filter applications…",
    "apps.no_match": "No application matches this filter.",
    "apps.view_cards": "Tile view",
    "apps.view_table": "Table view",
    "apps.col_name": "Application",
    "apps.col_criticality": "Criticality",
    "apps.col_findings": "Findings",
    "apps.col_scanners": "Scanners",
    "apps.scan_all_triggered": "Scan triggered on {n} applications",
    "apps.token_invalid": "Token looks invalid (must not contain / or spaces). Make sure you entered a Personal Access Token.",
    "apps.scan_triggered": "Scan triggered",
    "apps.delete_confirm": "Delete this application and all its findings?",
    "apps.deleted": "Application deleted",
    "apps.last_scan": "Last scan",
    "apps.never": "Never",
    "apps.no_apps": "No applications configured",
    "findings.title": "Findings",
    // Finding labels rebuilt from type/scanner + evidence — see ct_findings.js
    "finding.trivy_fs.title": "{cve}: {package}@{installed_version}",
    "finding.trivy_fs.desc": "Vulnerability {cve} affecting {package} {installed_version}.\n\n{original}",
    "finding.trivy_image.title": "{cve}: {package}@{installed_version} in {image}",
    "finding.trivy_image.desc": "Vulnerability {cve} affecting {package} {installed_version} (image {image}).\n\n{original}",
    "finding.gitleaks.title": "Secret detected: {rule} in {file}",
    "finding.gitleaks.desc": "A match for rule '{rule}' was found in {file}:{line}.\n\n{original}",
    "finding.semgrep.title": "SAST: {rule_id}",
    "finding.semgrep.desc": "The SAST rule {rule_id} was triggered in {file}:{line}.\n\n{original}",
    "findings.all_apps": "All applications",
    "findings.search_app": "Search an application…",
    "findings.all_severities": "All severities",
    "findings.all_scanners": "All scanners",
    "findings.all_statuses": "All statuses",
    "findings.search": "Search (title, target, CVE)...",
    "findings.triage": "Triage",
    "findings.status_new": "New",
    "findings.status_to_fix": "To Fix",
    "findings.status_false_positive": "False Positive",
    "findings.fp_bulk_title": "Mark as false positive",
    "findings.fp_bulk_label": "Justification (required)",
    "findings.fp_bulk_placeholder": "Why are these findings false positives? E.g.: component not exposed, mitigation in place, vulnerability not exploitable…",
    "findings.fp_bulk_required": "Justification is required",
    "findings.status_fixed": "Fixed",
    "findings.status_pending": "Pending",
    "findings.status_running": "Running",
    "findings.status_completed": "Completed",
    "findings.status_failed": "Failed",
    "findings.status_skipped": "Skipped",
    "scans.status_pending": "Pending",
    "scans.status_running": "Running",
    "scans.status_completed": "Completed",
    "scans.status_failed": "Failed",
    "scans.status_skipped": "Skipped",
    "findings.selected": "finding(s) selected",
    "findings.selected_n": "{n} finding(s) selected",
    "findings.col_title": "Title",
    "findings.choose_action": "Choose action",
    "findings.clear_selection": "Cancel",
    "findings.no_findings": "No findings",
    "findings.filter_severity": "Severity",
    "findings.filter_status": "Status",
    "findings.filter_scanner": "Scanner",
    "findings.filter_patch": "Patch",
    "findings.target": "Target",
    "findings.col_patch": "Patch",
    "findings.all_patches": "All patches",
    "findings.patch_available": "Patch available",
    "findings.patch_unavailable": "No patch",
    "findings.patch_none": "No patch",
    "findings.patch_status": "Vendor patch",
    "findings.installed_version": "Installed version",
    "dashboard.cve_patchable": "Patchable CVEs",
    "findings.evidence": "Evidence",
    "findings.ai_assist": "AI Assistant",
    "findings.first_seen": "First seen:",
    "findings.last_seen": "Last seen:",
    "findings.back": "Back",
    "sbom.title": "Software Bill of Materials",
    "sbom.all_ecosystems": "All ecosystems",
    "sbom.search": "Search package...",
    "sbom.export_csv": "Export CSV",
    "sbom.package": "Package",
    "sbom.version": "Version",
    "sbom.ecosystem": "Ecosystem",
    "sbom.license": "License",
    "sbom.direct": "Direct",
    "sbom.vulnerable": "Vulnerable",
    "sbom.parent": "Parent Dependency",
    "sbom.transitive": "transitive",
    "sbom.no_entries": "No SBOM entries",
    "sbom.vulnerable_only": "Vulnerable only",
    "scans.title": "Scan History",
    "scans.scanner": "Scanner",
    "scans.status": "Status",
    "measures.status_a_faire": "To do",
    "measures.status_en_cours": "In progress",
    "measures.status_termine": "Done",
    "scans.findings_count": "Findings",
    "scans.duration": "Duration",
    "scans.triggered_by": "Triggered by",
    "scans.reset_stuck": "Unblock",
    "scans.reset_stuck_tip": "Force-fail every stuck (running/pending) scan job for this application. Admin only.",
    "scans.reset_confirm": "Unblock all running/pending scans for \"{name}\"? They will be marked as failed.",
    "scans.reset_done": "{count} scan(s) unblocked.",
    "error.bad_request": "Invalid request",
    "error.forbidden": "Access denied",
    "error.not_found": "Resource not found",
    "error.conflict": "Data conflict",
    "error.validation": "Invalid data",
    "error.server": "Server error, please try again",
    "error.generic": "An error occurred",
    "scanner.trivy_fs": "Dependencies",
    "scanner.trivy_image": "Docker Images",
    "scanner.gitleaks": "Secrets",
    "scanner.semgrep": "SAST",
    "nav.ignore_rules": "Ignore Rules",
    "ignore.title": "Ignore Rules",
    "ignore.add": "Add a rule",
    "ignore.help": "Ignore rules auto-triage matching findings as false positive on every scan. Each rule requires a mandatory justification and is tracked in the audit log.",
    "ignore.empty": "No rules configured.",
    "ignore.col_scope": "Scope",
    "ignore.col_reason": "Reason",
    "ignore.col_by": "By",
    "ignore.all_apps": "All applications",
    "ignore.type.cve_id": "CVE ID",
    "ignore.type.package": "Package",
    "ignore.type.scanner_rule": "Scanner rule",
    "ignore.type.target_pattern": "Target pattern",
    "ignore.type.severity": "Severity",
    "ignore.type.ecosystem": "Ecosystem",
    "ignore.created": "Rule created",
    "ignore.updated": "Rule updated",
    "ignore.edit": "Edit rule",
    "ignore.deleted": "Rule deleted",
    "ignore.confirm_delete": "Delete this rule?",
    "ignore.err_required": "Reason is required",
    "ignore.err_no_criteria": "At least one criterion is required",
    "ignore.col_criteria": "Criteria",
    "ignore.add_criterion": "Add criterion (AND)",
    "ignore.search_apps": "Filter applications...",
    "ignore.reason_placeholder": "Confirmed false positive / Risk accepted / Not applicable...",
    "ignore.offer_title": "Create an ignore rule?",
    "ignore.offer_body": "This finding was marked as false positive. Would you like to create a rule to automatically ignore similar findings on future scans?",
    "ignore.offer_yes": "Create the rule",
    "ignore.offer_no": "No thanks",
    "nav.audit": "Audit log",
    "audit.title": "Audit Log",
    "audit.retention": "Retention",
    "audit.apply": "Apply",
    "audit.days": "days",
    "audit.search": "Search...",
    "audit.empty": "No audit entries",
    "audit.entries": "entries",
    "audit.col_date": "Date",
    "audit.col_user": "User",
    "audit.col_action": "Action",
    "audit.col_target": "Target",
    "audit.col_details": "Details",
    "audit.action.app.create": "Application created",
    "audit.action.app.update": "Application updated",
    "audit.action.app.delete": "Application deleted",
    "audit.action.scan.trigger": "Scan triggered",
    "audit.action.finding.triage": "Finding triaged",
    "audit.action.finding.bulk_triage": "Bulk triage",
    "audit.action.ignore_rule.create": "Ignore rule created",
    "audit.action.ignore_rule.update": "Ignore rule updated",
    "audit.action.ignore_rule.delete": "Ignore rule deleted",
    "nav.aide": "HELP",
    "nav.methodo": "Methodology",
    "nav.usage": "User guide",
    "help.tab_methodo": "AppSec Methodology",
    "help.tab_usage": "User Guide",
    "help.methodo_html": "<h1 class=\"heading-blue\">AppSec (SAST/SCA) — Methodology</h1>"
        + "<p class=\"text-muted\">Continuous detection of application vulnerabilities: dependencies (SCA), source code (SAST), secrets and container images.</p>"
        + "<h2>1. Shift-left approach</h2>"
        + "<p>The module applies the <strong>shift-left</strong> principle: detect vulnerabilities as early as possible in the development lifecycle, where fixing them is cheapest. Code repositories and published images are analysed continuously, rather than during one-off audits.</p>"
        + "<h2>2. The four analysis families</h2>"
        + "<table><tr><th>Family</th><th>Engine</th><th>What is detected</th></tr>"
        + "<tr><td>SCA (dependencies)</td><td>Trivy FS</td><td>Known CVEs in declared dependencies (<code>requirements.txt</code>, <code>package.json</code>, <code>go.sum</code>, <code>Gemfile.lock</code>…)</td></tr>"
        + "<tr><td>Container images</td><td>Trivy Image</td><td>CVEs in system packages (apt, apk) and dependencies embedded in image layers</td></tr>"
        + "<tr><td>Secrets</td><td>Gitleaks</td><td>Committed API keys, tokens, passwords and certificates, including in Git history</td></tr>"
        + "<tr><td>SAST (source code)</td><td>Semgrep</td><td>Code vulnerabilities: SQL injection, XSS, insecure deserialization, SSRF…</td></tr></table>"
        + "<h3>SCA — software composition analysis</h3>"
        + "<p>Each CVE reports the affected package, the installed version and, when it exists, the <em>fixed version</em> published by the vendor. This underpins the <strong>quick-wins</strong> doctrine: a CVE with a patch is fixed by a simple version bump.</p>"
        + "<ul><li>Keep dependencies up to date (Renovate, Dependabot)</li>"
        + "<li>Fix CVEs with an available vendor patch first</li>"
        + "<li>Assess the real risk of unpatched CVEs (exposure, WAF, feature toggle)</li></ul>"
        + "<h3>Container images</h3>"
        + "<p>The analysis covers the published image layers, not the source code: it complements SCA, which scans code before the build. An image can be vulnerable while the code is not (outdated system packages in the base image).</p>"
        + "<ul><li>Use minimal base images (<code>-slim</code>, <code>-alpine</code>, distroless)</li>"
        + "<li>Rebuild regularly to pick up base-image fixes</li></ul>"
        + "<h3>Secret detection</h3>"
        + "<div class=\"help-tip\"><strong>Doctrine:</strong> a secret present in Git history is considered compromised, even if removed in a later commit. The only valid remediation is <strong>rotation</strong>; deleting it from the code is not enough.</div>"
        + "<ul><li>Externalise secrets (gitignored <code>.env</code> files, a secrets manager such as Vault)</li>"
        + "<li>Block commits containing secrets with a pre-commit hook</li></ul>"
        + "<h3>SAST — static code analysis</h3>"
        + "<p>Semgrep applies declarative rules from the <strong>OWASP Top 10</strong>, default and language-specific rulesets (Python, JavaScript, TypeScript). SAST structurally produces more false positives than SCA: fast, justified triage is essential to maintain trust in the tool.</p>"
        + "<h2>3. Severity model</h2>"
        + "<p>Findings are classified on the suite-wide harmonised scale, derived from the CVSS score:</p>"
        + "<table><tr><th>Level</th><th>Indicative CVSS</th><th>Expected handling</th></tr>"
        + "<tr><td><strong>Critical</strong></td><td>9.0 – 10.0</td><td>Immediate fix, outside the release cycle if needed</td></tr>"
        + "<tr><td><strong>High</strong></td><td>7.0 – 8.9</td><td>Priority fix, scheduled short-term</td></tr>"
        + "<tr><td><strong>Medium</strong></td><td>4.0 – 6.9</td><td>Fix planned within the normal cycle</td></tr>"
        + "<tr><td><strong>Low</strong></td><td>0.1 – 3.9</td><td>Opportunistic fix (next version bump)</td></tr>"
        + "<tr><td><strong>Info</strong></td><td>—</td><td>Informational, no direct risk</td></tr></table>"
        + "<p>Prioritisation combines three factors: the finding's <strong>severity</strong>, the <strong>criticality</strong> of the affected application, and <strong>vendor patch availability</strong>. A high CVE with a patch on a critical application comes before an unpatched critical CVE on a secondary one.</p>"
        + "<h2>4. Triage and remediation doctrine</h2>"
        + "<p>Each finding follows a lifecycle:</p>"
        + "<table><tr><th>Status</th><th>Meaning</th></tr>"
        + "<tr><td><strong>New</strong></td><td>Detected, not yet analysed by a human</td></tr>"
        + "<tr><td><strong>To Fix</strong></td><td>Confirmed as a real vulnerability, awaiting remediation</td></tr>"
        + "<tr><td><strong>False Positive</strong></td><td>Incorrect detection or non-applicable risk — justification required</td></tr>"
        + "<tr><td><strong>Fixed</strong></td><td>Remediation applied, to be confirmed by a re-scan</td></tr></table>"
        + "<p>Principles:</p>"
        + "<ul><li>Every confirmed finding gets a <strong>remediation</strong> with an owner and a deadline — no vulnerability left \"known but unowned\"</li>"
        + "<li>Every false-positive classification is <strong>justified and tracked</strong> in the audit log</li>"
        + "<li>Recurring false positives are industrialised through <strong>ignore rules</strong>: a justified, audited auto-classification — never a silent deletion</li>"
        + "<li>A \"Fixed\" status only holds if the finding does not reappear on the next scan (cross-scan deduplication)</li></ul>"
        + "<h2>5. SBOM and traceability</h2>"
        + "<p>The <strong>SBOM</strong> (Software Bill of Materials) inventories every software component, direct and transitive, with versions and licences. It is the rapid-response tool for major vulnerabilities: during a \"Log4Shell\", it answers \"where do we use this component?\" in seconds.</p>"
        + "<h2>6. Frameworks</h2>"
        + "<ul><li><strong>OWASP Top 10</strong> — foundation of the SAST rules and secure-coding training</li>"
        + "<li><strong>CVE / NVD</strong> — public vulnerability registry, source of identifiers and detail links</li>"
        + "<li><strong>CVSS</strong> — scoring system (0-10) from which the severity model above derives</li></ul>"
        + "<h2>7. Glossary</h2>"
        + "<table><tr><th>Term</th><th>Definition</th></tr>"
        + "<tr><td>SCA</td><td>Software Composition Analysis — third-party dependency analysis</td></tr>"
        + "<tr><td>SAST</td><td>Static Application Security Testing — static source code analysis</td></tr>"
        + "<tr><td>SBOM</td><td>Software Bill of Materials — software component inventory</td></tr>"
        + "<tr><td>CVE</td><td>Common Vulnerabilities and Exposures — unique vulnerability identifier</td></tr>"
        + "<tr><td>CVSS</td><td>Common Vulnerability Scoring System — severity score (0-10)</td></tr>"
        + "<tr><td>Shift-left</td><td>Integrating security as early as possible in the development cycle</td></tr>"
        + "<tr><td>Dedup</td><td>Deduplication — matching identical findings across successive scans</td></tr></table>"
        + "<h2>8. CISO Toolbox suite integration</h2>"
        + "<p>In a suite deployment, this module's <strong>remediations</strong> automatically flow up into <strong>Pilot's action plan</strong> (the governance hub), where they are consolidated with items from the other modules under the shared term <strong>Action</strong>, and can be grouped into <strong>projects</strong> to drive cross-cutting progress. The module remains the authority for its own domain — Pilot only consolidates.</p>",
    "help.usage_html": "<h1 class=\"heading-blue\">AppSec (SAST/SCA) — User Guide</h1>\n\n<h2>Features requiring AI</h2>\n<p>These features call a language model and are only available once AI is configured. They are <strong>optional</strong>: without configuration they are hidden or inactive and the rest of the module works normally.</p>\n<ul>\n<li><strong>AI analysis of a finding</strong>: triage recommendation, with a <em>deep analysis</em> option that feeds more context to the model</li>\n</ul>\n<p class=\"help-tip\">Where to configure: in a standalone install, through the module's <strong>Settings &rarr; AI</strong> (your own API key). In the suite, keys are centralised by <strong>Pilot</strong> and pushed to the modules &mdash; nothing to enter here, and AI access is granted per user in the permissions matrix.</p>"
        + "<p class=\"text-muted\">Pages, buttons and workflows of the module. Navigation is done through the sidebar; the app bar provides language (FR/EN), light/dark theme and settings (AI assistant).</p>"
        + "<h2>1. Dashboard</h2>"
        + "<p>Tiles: application count, active findings by severity (Critical, High, Medium, Low) and <strong>Patchable CVEs</strong> (count and percentage of active CVEs with a vendor patch). Each tile is clickable and opens the corresponding filtered list. The <strong>By Application</strong> table breaks findings down per severity (clickable rows); <strong>Recent Scans</strong> shows the last 10 scans.</p>"
        + "<h2>2. Applications</h2>"
        + "<p>Each application represents a scan scope, displayed as a card (criticality, last scan, severity badges, scanner count). Buttons: <strong>Add Application</strong>, <strong>Scan All</strong>; on each card: trigger a scan (▶) or <strong>Configure</strong>. Clicking the card opens the detail view: configuration summary and the application's findings, filterable (severity, status, scanner, search).</p>"
        + "<p>Configuration form:</p>"
        + "<ul><li><strong>Name, description, criticality, scan frequency</strong> (hours between automatic scans)</li>"
        + "<li><strong>Source code analysis</strong>: Git repository URL, branch (default <code>main</code>), PAT access token for private repos (encrypted at rest), <strong>Directories to scan</strong> (monorepo — one path per line relative to repo root, <code>..</code> forbidden), Dependencies / Secrets / SAST checkboxes</li>"
        + "<li><strong>Docker image scanning</strong>: enable checkbox, image list (one per line, GHCR / Docker Hub / private registry), registry token for private images (encrypted at rest)</li></ul>"
        + "<div class=\"help-tip\"><strong>Warning:</strong> deleting an application also deletes all its findings.</div>"
        + "<h2>3. Findings</h2>"
        + "<p>List of all detections. Pill filters: <strong>severity</strong> (Critical, High, Medium, Low, Info), <strong>status</strong>, <strong>scanner</strong> (Dependencies, Docker Images, Secrets, SAST), <strong>patch</strong> (Patch available / No patch); plus an application dropdown and text search (title, target, CVE).</p>"
        + "<div class=\"help-tip\"><strong>Tip:</strong> the list opens filtered on the <strong>New</strong> status. Click \"All statuses\" to also see already-triaged findings.</div>"
        + "<p><strong>Columns:</strong> severity, title (+ CVE), target, application, scanner, patch (green badge with the fixed version, red \"No patch\"), status.</p>"
        + "<p><strong>Finding detail:</strong> click a row — description, evidence, installed vs fixed version, first/last seen dates, linked remediation if any, triage buttons and AI assistant.</p>"
        + "<p><strong>Bulk triage:</strong> tick several rows then use the action bar at the bottom:</p>"
        + "<ul><li><strong>To Fix</strong> — opens the remediation form: a single remediation covers the whole selection (title, description, owner via the directory, deadline)</li>"
        + "<li><strong>Fixed</strong> — marks the selection as remediated</li>"
        + "<li><strong>False Positive</strong> — mandatory justification, then an offer to create a pre-filled ignore rule</li></ul>"
        + "<h2>4. AI Assistant</h2>"
        + "<p>Enable it in the <strong>settings</strong> (app bar icon). On a finding's detail view, the AI analysis button opens a form: optional analyst context, and a <strong>deep analysis</strong> option that fetches the source file at the scanned commit (requires a configured repository). The result gives a probable true/false positive verdict with a confidence level, a severity recommendation, a summary, remediation guidance and references.</p>"
        + "<h2>5. SBOM</h2>"
        + "<p>Inventory of all packages (direct and transitive) detected by scans. Filters: application, ecosystem (dynamic list: npm, pypi, go…), <strong>Vulnerable only</strong> checkbox, name search. Transitive dependencies show their <strong>parent dependency</strong> (clickable link that filters the list). CVE badges open the NVD page: red = active CVE, greyed = triaged CVE (false positive, fixed). <strong>Export CSV</strong> button in the top right (honours the application filter).</p>"
        + "<h2>6. Scans</h2>"
        + "<p>History of all scans: application, scanner, status (Pending, Running, Completed, Failed, Skipped), findings count, triggered by, date and error message if any. For admins, the <strong>Unblock</strong> button force-fails stuck scans (running/pending).</p>"
        + "<h2>7. Action Plan</h2>"
        + "<p>Remediations created from Findings (\"To Fix\" action). Columns: ID, title, number of covered findings, status (To do, In progress, Done), owner, deadline. Clicking a row opens the remediation: edit, progress log (timestamped notes), delete. Multi-select: bulk <strong>Done</strong> or <strong>Delete</strong>.</p>"
        + "<h2>8. Ignore Rules (admin)</h2>"
        + "<p>Auto-triage of recurring false positives. A rule combines one or more criteria (AND logic):</p>"
        + "<table><tr><th>Type</th><th>Description</th><th>Example</th></tr>"
        + "<tr><td><code>cve_id</code></td><td>Exact CVE</td><td><code>CVE-2024-1234</code></td></tr>"
        + "<tr><td><code>package</code></td><td>Package name (glob)</td><td><code>lodash</code>, <code>com.fasterxml.*</code></td></tr>"
        + "<tr><td><code>scanner_rule</code></td><td>Scanner rule ID</td><td><code>generic-api-key</code></td></tr>"
        + "<tr><td><code>target_pattern</code></td><td>Path or target (glob)</td><td><code>tests/*</code>, <code>*.test.js</code></td></tr>"
        + "<tr><td><code>severity</code></td><td>Exact severity</td><td><code>low</code>, <code>info</code></td></tr>"
        + "<tr><td><code>ecosystem</code></td><td>Package ecosystem</td><td><code>npm</code>, <code>pypi</code></td></tr></table>"
        + "<p>Scope: all applications or a selection (search field). Mandatory justification. Each rule can be toggled ON/OFF, edited or deleted. On creation or edit, matching existing findings (New, To Fix) are <strong>retroactively auto-triaged</strong> as false positive. After a manual false-positive triage, the module offers to create a rule pre-filled with the finding's criteria.</p>"
        + "<h2>9. Audit Log (admin)</h2>"
        + "<p>Trace of module actions: date, user, action, target, details, IP address. Text search and configurable retention (in days) at the top of the page.</p>"
        + "<h2>10. Tips</h2>"
        + "<table><tr><th>Action</th><th>How</th></tr>"
        + "<tr><td>Quick wins</td><td>Dashboard → \"Patchable CVEs\" tile → list of CVEs with a vendor patch</td></tr>"
        + "<tr><td>Quick triage</td><td>Findings → tick several rows → action bar at the bottom</td></tr>"
        + "<tr><td>See already-triaged findings</td><td>Findings → \"All statuses\" pill</td></tr>"
        + "<tr><td>Scan one application</td><td>Applications → app card → \"Scan Now\"</td></tr>"
        + "<tr><td>Scan the whole portfolio</td><td>Applications → \"Scan All\" button</td></tr>"
        + "<tr><td>Export the SBOM</td><td>SBOM → \"Export CSV\" button</td></tr>"
        + "<tr><td>Find who uses a package</td><td>SBOM → search by package name</td></tr></table>",
});
