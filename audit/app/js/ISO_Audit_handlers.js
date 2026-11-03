// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_auditNewMeasure", "_auditPickerDel", "_auditPickerDup", "_auditPickerImport", "_auditPickerNew",
    "_auditPickerOpen", "_closeAuditPicker", "_editAuditMeasure", "_logout", "_openAuditPicker",
    "addImage", "copyQuestion", "cycleDocStatus", "deleteImage", "deleteSlot", "exportCSV",
    "exportPlanningCSV", "exportPlanningWord", "exportWord", "generatePlanning", "generateReport",
    "goToSearchResult", "onFilterHDS", "onFilterStatus", "onFilterText", "onMetaChange",
    "onPlanningParam", "onSearchInput", "onSearchScope", "onSlotDomain", "selectPanel", "setDocObs",
    "setField", "setStatus", "toggleQuestions", "viewImage"
]);
