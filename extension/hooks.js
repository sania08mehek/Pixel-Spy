// hooks.js — PixelSpy MAIN WORLD interceptor
// Runs in the page's JavaScript context (world: MAIN).
// Patches fetch and XHR, then posts events to the isolated world via postMessage.
// NO chrome.* API access here — communicate only via postMessage.

(function () {
    "use strict";

    const SRC = "pixelspy-hooks";

    function postToIsolated(type, data) {
        window.postMessage({ source: SRC, type, ...data }, "*");
    }

    // ── Fetch Hook ────────────────────────────────────────────────────────────
    const _fetch = window.fetch;
    window.fetch = async function (...args) {
        const url    = typeof args[0] === "string" ? args[0] : (args[0] && args[0].url) || "";
        const method = ((args[1] && args[1].method) || "GET").toUpperCase();
        postToIsolated("FETCH", { url, method });
        return _fetch.apply(this, args);
    };

    // ── XHR Hook ──────────────────────────────────────────────────────────────
    const _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        postToIsolated("XHR", { url: url || "", method: (method || "GET").toUpperCase() });
        return _open.apply(this, [method, url, ...rest]);
    };

    console.log("PixelSpy: hooks.js loaded in MAIN world ✓");
})();
