// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_closeModal", "_logout", "_toggleSidebarMobile", "_watchAlertsBulkSetStatus",
    "_watchAlertsBulkToggle", "_watchAlertsBulkToggleAll", "addRecipientToScope", "addTargetToScope",
    "confirmDeleteScope", "forceSendDigest", "onAlertSearch", "onRecipientInputChange",
    "openAlertDetail", "openDigestBody", "openDigestPreview", "openScopeCreate", "openScopeDetails",
    "removeRecipientFromScope", "removeTargetFromScope", "runAlertAnalysis", "runFeedNow", "saveScope",
    "selectPanel", "setAlertFilter", "setAlertKev", "toggleTargetEnabled"
]);
