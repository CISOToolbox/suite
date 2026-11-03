// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_bulkAccessMeasuresDelete", "_bulkAccessMeasuresDone", "_bulkDeleteApps", "_bulkDeleteUsers",
    "_clearReviewFilters", "_editAccessMeasureRow", "_entPerimOpen", "_entPerimSearch", "_entPickPerim",
    "_filterApps", "_filterUsers", "_logout", "_openAppRow", "_openUserRow", "_plgCancel", "_plgSave",
    "_plgSearchFilter", "_plgSelectType", "_plgTestInline", "_refreshMeasures",
    "_requestEntryDerogation", "_toggleReviewFilter", "_toggleReviewListFilter", "addApp",
    "addAppReviewer", "addEntitlement", "addMeasure", "addServiceAccount", "addUser", "backToApps",
    "backToReviews", "backToSA", "backToUsers", "closeReview", "deleteApp", "deletePlugin",
    "deleteReviewFromApp", "deleteServiceAccount", "deleteUser", "downloadCsvTemplate",
    "downloadUsersCsvTemplate", "importAppsCsv", "importReviewCsv", "importReviewFromConnector",
    "importUsersCsv", "openReview", "openSA", "removeAppReviewer", "removeEntitlement", "saveAppField",
    "saveAppRoles", "saveSAField", "saveUserField", "selectPanel", "setDecision", "showPluginHistory",
    "showPluginModal", "startReview", "syncAppsFromAsset", "syncUsersFromHr", "syncUsersFromPilot",
    "testPlugin"
]);
