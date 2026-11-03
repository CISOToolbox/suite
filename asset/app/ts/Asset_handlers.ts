// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_aplgTypeChanged", "_bulkAssetsAddToGroup", "_bulkAssetsDelete", "_bulkAssetsEdit",
    "_bulkAssetsRetire", "_clearManualLocks", "_deleteCustomType", "_editAssetMeasureRow",
    "_groupePickerFilter", "_logout", "_newAssetMeasure", "_openAssetRow", "_openGroupeAssetPicker",
    "_sortAssets", "_toggleAssetCol", "_toggleAssetColsPopup", "addAsset", "addAssetDep",
    "addAssetGroupe", "addGroupe", "addGroupeDep", "addRaciRow", "aiSuggestDescription",
    "aiSuggestPolitiques", "aiSuggestPrincipe", "aiSuggestRaci", "backToAssets", "backToGroupes",
    "deleteAsset", "deleteAssetPlugin", "deleteGroupe", "exportEcheancesIcs", "filterAssetCrit",
    "filterAssetStatut", "filterAssetType", "filterAssets", "importCsvDialog", "openAssetTypesModal",
    "openEcheanceAsset", "openGroupe", "refreshConnectors", "removeAssetDep", "removeAssetGroupe",
    "removeGroupeAsset", "removeGroupeDep", "removeRaciRow", "saveAssetField", "saveGroupeField",
    "saveGroupePol", "saveGroupePolCheck", "saveLicenceField", "saveRaciActivite", "saveRaciCell",
    "selectPanel", "showAssetPluginHistory", "showPluginModal", "switchGroupeTab", "syncAssetPlugin",
    "testAssetPlugin"
]);
