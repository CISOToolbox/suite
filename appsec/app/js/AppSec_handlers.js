// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_adSetScanner", "_adSetSearch", "_adSetSev", "_adSetStatus", "_addIgnoreRule", "_aiTriageFinding",
    "_aiTriageRun", "_appsSearch", "_appsSetView", "_appsecTriageDetail", "_backToApps",
    "_backToFindings", "_bulkAppsecFindingsFP", "_bulkAppsecFindingsFixed", "_bulkAppsecFindingsToFix",
    "_bulkAppsecMeasuresDelete", "_bulkAppsecMeasuresDone", "_closeAppModal", "_dashNav",
    "_dashNavPatch", "_dashNavSev", "_deleteApp", "_deleteAppFromDetail", "_deleteAppsecFinding",
    "_deleteIgnoreRule", "_editAppDialog", "_editAppsecMeasureRow", "_editIgnoreRule", "_irAddCrit",
    "_irFilterApps", "_irRemoveCrit", "_irToggleAllApps", "_logout", "_openAppFindings",
    "_openFindingRow", "_openNotifPrefs", "_requestDerogationDetail", "_resetStuckScans", "_saveApp",
    "_saveAuditRetention", "_sbomFilterByPkg", "_scanAllApps", "_setAuditSearch", "_setFPatch",
    "_setFScanner", "_setFSearch", "_setFSev", "_setFStatus", "_setSEco", "_setSSearch", "_setSVuln",
    "_toggleIgnoreRule", "_toggleImageSection", "_triggerScan", "exportReport", "importApps",
    "selectPanel", "showAddApp"
]);
