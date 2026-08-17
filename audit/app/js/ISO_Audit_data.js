var _ASSET_BASE = "js/ISO_Audit";
// EN translations loaded statically in index.html — mark as loaded to prevent re-fetch
if (typeof _i18nLoaded !== "undefined")
    _i18nLoaded["en"] = true;
window.ISO_AUDIT_INIT_DATA = {
    meta: {
        name: "",
        ref: "",
        date: "",
        auditor: "",
        scope: "",
        hds: "non"
    },
    findings: {},
    doc_review: {},
    planning: {
        params: {
            start_date: "",
            days: 3,
            start_time: "09:00",
            slot_duration: 60,
            lunch_start: "12:30",
            lunch_duration: 60
        },
        slots: []
    },
    journal: [],
    timers: {}
};
