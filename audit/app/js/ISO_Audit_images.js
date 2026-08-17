// ═══════════════════════════════════════════════════════════════════════
// ISO Audit — IMAGE MANAGEMENT (IndexedDB)
// ═══════════════════════════════════════════════════════════════════════
(function () {
    "use strict";
    var DB_NAME = "iso_audit_images";
    var STORE_NAME = "images";
    var DB_VERSION = 1;
    var _db = null;
    // ── IndexedDB helpers ───────────────────────────────────────────────
    function _openDB(cb) {
        if (_db) {
            cb(_db);
            return;
        }
        var req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = function (e) {
            var db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: "id" });
            }
        };
        req.onsuccess = function (e) { _db = e.target.result; cb(_db); };
        req.onerror = function () { console.error("IndexedDB error"); cb(null); };
    }
    function _imgSave(ctrlId, dataUrl, name, cb) {
        _openDB(function (db) {
            if (!db) {
                if (cb)
                    cb(null);
                return;
            }
            var id = "img_" + Date.now() + "_" + Math.random().toString(36).substr(2, 5);
            var entry = { id: id, ctrlId: ctrlId, data: dataUrl, name: name || "image.jpg", ts: new Date().toISOString() };
            var tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).put(entry);
            tx.oncomplete = function () {
                // Add ref to D.findings
                var f = getFinding(ctrlId);
                if (!f.images)
                    f.images = [];
                f.images.push(id);
                _autoSave();
                if (cb)
                    cb(id);
            };
            tx.onerror = function () { if (cb)
                cb(null); };
        });
    }
    window._imgSave = _imgSave;
    function _imgGet(imgId, cb) {
        _openDB(function (db) {
            if (!db) {
                cb(null);
                return;
            }
            var req = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(imgId);
            req.onsuccess = function () { cb(req.result || null); };
            req.onerror = function () { cb(null); };
        });
    }
    window._imgGet = _imgGet;
    function _imgGetAll(ctrlId, cb) {
        var f = getFinding(ctrlId);
        var ids = f.images || [];
        if (ids.length === 0) {
            cb([]);
            return;
        }
        _openDB(function (db) {
            if (!db) {
                cb([]);
                return;
            }
            var results = [];
            var pending = ids.length;
            ids.forEach(function (id) {
                var req = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(id);
                req.onsuccess = function () {
                    if (req.result)
                        results.push(req.result);
                    if (--pending === 0)
                        cb(results);
                };
                req.onerror = function () { if (--pending === 0)
                    cb(results); };
            });
        });
    }
    window._imgGetAll = _imgGetAll;
    function _imgDelete(imgId, ctrlId, cb) {
        _openDB(function (db) {
            if (!db) {
                if (cb)
                    cb();
                return;
            }
            var tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).delete(imgId);
            tx.oncomplete = function () {
                // Remove ref from D.findings
                var f = getFinding(ctrlId);
                if (f.images) {
                    f.images = f.images.filter(function (id) { return id !== imgId; });
                }
                _autoSave();
                if (cb)
                    cb();
            };
        });
    }
    window._imgDelete = _imgDelete;
    // ── Image compression ───────────────────────────────────────────────
    function _imgCompress(file, maxW, quality, cb) {
        var reader = new FileReader();
        reader.onload = function (e) {
            var img = new Image();
            img.onload = function () {
                var w = img.width, h = img.height;
                if (w > maxW) {
                    h = Math.round(h * (maxW / w));
                    w = maxW;
                }
                var canvas = document.createElement("canvas");
                canvas.width = w;
                canvas.height = h;
                var ctx = canvas.getContext("2d");
                ctx.drawImage(img, 0, 0, w, h);
                var dataUrl = canvas.toDataURL("image/jpeg", quality);
                cb(dataUrl);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
    // ── UI: Add image ───────────────────────────────────────────────────
    function addImage(ctrlId) {
        var input = document.createElement("input");
        input.type = "file";
        input.accept = "image/*";
        input.multiple = true;
        input.onchange = function () {
            var files = Array.from(input.files || []);
            if (files.length === 0)
                return;
            var pending = files.length;
            files.forEach(function (file) {
                _imgCompress(file, 800, 0.7, function (dataUrl) {
                    _imgSave(ctrlId, dataUrl, file.name, function (imgId) {
                        if (--pending === 0) {
                            renderImages(ctrlId);
                            showStatus(t("audit.images.added"));
                        }
                    });
                });
            });
        };
        input.click();
    }
    window.addImage = addImage;
    function deleteImage(ctrlId, imgId) {
        _saveState();
        _imgDelete(imgId, ctrlId, function () {
            renderImages(ctrlId);
            showStatus(t("audit.images.deleted"));
        });
    }
    window.deleteImage = deleteImage;
    function viewImage(imgId) {
        _imgGet(imgId, function (entry) {
            if (!entry)
                return;
            var overlay = document.getElementById("image-overlay");
            if (!overlay) {
                overlay = document.createElement("div");
                overlay.id = "image-overlay";
                overlay.className = "img-overlay";
                overlay.innerHTML = '<div class="img-overlay-content"><img id="image-overlay-img"><div class="img-overlay-name" id="image-overlay-name"></div></div>';
                overlay.onclick = function (e) { if (e.target === overlay || e.target.className === "img-overlay-content")
                    overlay.classList.remove("open"); };
                document.body.appendChild(overlay);
            }
            document.getElementById("image-overlay-img").src = entry.data;
            document.getElementById("image-overlay-name").textContent = entry.name || "";
            overlay.classList.add("open");
        });
    }
    window.viewImage = viewImage;
    // ── UI: Render thumbnails ───────────────────────────────────────────
    function renderImages(ctrlId) {
        var container = document.getElementById("images-" + ctrlId.replace(/\./g, "-"));
        if (!container)
            return;
        _imgGetAll(ctrlId, function (images) {
            var h = '<div class="img-thumbs">';
            images.forEach(function (img) {
                h += '<div class="img-thumb">';
                var safeSrc = (img.data && img.data.indexOf("data:image/") === 0) ? img.data : "";
                h += '<img src="' + safeSrc + '" data-click="viewImage" data-args=\'' + _da(img.id) + '\'>';
                h += '<button class="img-thumb-del" data-click="deleteImage" data-args=\'' + _da(ctrlId, img.id) + '\'>&times;</button>';
                h += '</div>';
            });
            h += '<button class="img-add-btn" data-click="addImage" data-args=\'' + _da(ctrlId) + '\'>+ ' + t("audit.images.add") + '</button>';
            h += '</div>';
            container.innerHTML = h;
        });
    }
    window.renderImages = renderImages;
    // ── Export: embed all images into a data object for JSON save ────────
    function _imgExportAll(cb) {
        _openDB(function (db) {
            if (!db) {
                cb([]);
                return;
            }
            var tx = db.transaction(STORE_NAME, "readonly");
            var req = tx.objectStore(STORE_NAME).getAll();
            req.onsuccess = function () { cb(req.result || []); };
            req.onerror = function () { cb([]); };
        });
    }
    function _imgImportAll(images, cb) {
        _openDB(function (db) {
            if (!db || !images || images.length === 0) {
                if (cb)
                    cb();
                return;
            }
            var tx = db.transaction(STORE_NAME, "readwrite");
            var store = tx.objectStore(STORE_NAME);
            images.forEach(function (img) { store.put(img); });
            tx.oncomplete = function () { if (cb)
                cb(); };
            tx.onerror = function () { if (cb)
                cb(); };
        });
    }
    // Hook into cisotoolbox.js serialization/deserialization
    // Override _serializeForSave to include images
    var _origSerialize = window._serializeForSave;
    if (typeof _origSerialize === "function") {
        window._serializeForSave = async function () {
            // Collect images from IndexedDB
            return new Promise(function (resolve) {
                _imgExportAll(function (images) {
                    // Temporarily add images to D for serialization
                    D._images = images;
                    _origSerialize().then(function (blob) {
                        delete D._images;
                        resolve(blob);
                    });
                });
            });
        };
    }
    // Hook into _loadBuffer to restore images after JSON load
    var _origInitDataAndRender = window._initDataAndRender;
    if (typeof _origInitDataAndRender === "function") {
        window._initDataAndRender = function (afterFn) {
            // Check if D has _images from loaded file
            if (D._images && D._images.length > 0) {
                var images = D._images;
                delete D._images;
                _imgImportAll(images, function () {
                    _origInitDataAndRender(afterFn);
                });
            }
            else {
                delete D._images;
                _origInitDataAndRender(afterFn);
            }
        };
    }
})();
