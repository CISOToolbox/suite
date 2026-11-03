// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_addSelectedMeasures", "_aiAddSuggestedMeasures", "_aiApplySuggestedPlan", "_aiClosePanel",
    "_aiCreateSuggestedGroups", "_aiSuggestGroups", "_aiSuggestMeasures", "_aiSuggestProjects",
    "_aiToggleAllMeasures", "_backToProjects", "_bkClearSelection", "_bkFilterChanged", "_bkSelectTab",
    "_bkToggleAll", "_bkToggleOne", "_bulkPilotMeasuresDelete", "_changeModPerm", "_changeRole",
    "_clearAiKey", "_connDeleteConfig", "_connNewInstance", "_connOpenConfig", "_connOpenInstance",
    "_connRunNow", "_connRunTest", "_connSetFilter", "_connTestInstance", "_deleteBackup",
    "_deleteProject", "_deleteSelectedBackups", "_deleteUser", "_detachGroupMember", "_dirAddPerson",
    "_dirEditPerson", "_dirExportForAccess", "_dirImportCsv", "_downloadBackup", "_editEvidence",
    "_editProject", "_filterEvidences", "_filterMeasures", "_kpiAddMapping", "_kpiAddSelectedMappings",
    "_kpiAutoCompute", "_kpiAwarenessExport", "_kpiDetailDelete", "_kpiDetailSubmitManual",
    "_kpiOpenAutoPicker", "_kpiOpenCreate", "_kpiOpenDetail", "_kpiOpenHistory", "_kpiPickerActivate",
    "_kpiRemoveMapping", "_kpiSetFilter", "_kpiSuggestFrameworks", "_kpiToggleActive",
    "_linkSelectedMeasures", "_logout", "_newProject", "_openGroupMemberModule", "_openGroupRow",
    "_openMeasure", "_openMeasureRow", "_openModule", "_openNotifPrefs", "_removeMeasure",
    "_restoreBackup", "_resyncModules", "_rstCloseSession", "_rstExplore", "_rstExploreBefore",
    "_rstModuleChanged", "_rstObjApply", "_rstObjDiff", "_rstPromote", "_rstRefreshJournal",
    "_runAllBackups", "_runBackup", "_saveBackupConfig", "_saveProject", "_saveSettings",
    "_searchMeasuresToAdd", "_setMeasureView", "_showNewMeasureForm", "_syncEvidencesNow",
    "_syncMeasuresNow", "_toggleAI", "selectPanel"
]);
