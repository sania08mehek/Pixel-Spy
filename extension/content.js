// content.js — PixelSpy isolated world content script
// Listens to postMessage events from hooks.js (MAIN world), runs SQLi scoring,
// monitors DOM mutations, and responds to chrome.runtime messages from the panel.

// ── State ─────────────────────────────────────────────────────────────────────

let currentReport = {
    url: location.href,
    scanTime: null,
    issues: [],   // issue objects from both engines
    events: [],   // runtime events (fetch, XHR, DOM mutations)
    attackSurface: null,
    securityScore: null
};

// ── Utility ───────────────────────────────────────────────────────────────────

function trimEvents() {
    if (currentReport.events.length > 200) {
        currentReport.events = currentReport.events.slice(-200);
    }
}

function runtimeId() {
    return `rt_${Date.now()}_${Math.floor(Math.random() * 9999)}`;
}

// ── Security Score Refresh ────────────────────────────────────────────────────

function refreshSecurityScore() {
    if (typeof window.calculateSecurityScore === "function") {
        currentReport.securityScore = window.calculateSecurityScore(
            currentReport.issues,
            currentReport.attackSurface
        );
        console.log("PixelSpy: Runtime score updated:", currentReport.securityScore.overall);
    }
}

// ── postMessage Listener (receives events from hooks.js in MAIN world) ─────────

window.addEventListener("message", (event) => {
    // Only accept messages from our own hooks.js
    if (!event.data || event.data.source !== "pixelspy-hooks") return;

    const { type, url, method } = event.data;

    if (type === "FETCH" || type === "XHR") {
        const evt = {
            type,
            url: url || "",
            method: method || "GET",
            timestamp: Date.now(),
            flag: null
        };

        // SQLi heuristic check
        if (typeof window.scoreRequestForSQLi === "function") {
            const sqliResult = window.scoreRequestForSQLi(url, method);
            if (sqliResult) {
                evt.flag = "SQLi";
                const isDup = currentReport.issues.some(
                    i => i.type === "SQLi" && i.url === url && i.score === sqliResult.score
                );
                if (!isDup) {
                    currentReport.issues.push(sqliResult);
                    refreshSecurityScore();
                    console.log("PixelSpy: SQLi issue detected via", type, sqliResult);
                }
            }
        }

        currentReport.events.push(evt);
        trimEvents();
    }
});

// ── MutationObserver Hook (DOM XSS detection) ─────────────────────────────────

(function hookDOM() {
    const observer = new MutationObserver(mutations => {
        mutations.forEach(m => {
            // ── Attribute changes (src / href) ────────────────────────────────
            if (m.type === "attributes" &&
                (m.attributeName === "src" || m.attributeName === "href")) {
                const val    = m.target.getAttribute(m.attributeName) || "";
                const isXss  = val.toLowerCase().startsWith("javascript:");

                const event = {
                    type: "DOM",
                    detail: `${m.attributeName} changed on <${m.target.tagName.toLowerCase()}>`,
                    value: val.substring(0, 80),
                    timestamp: Date.now(),
                    flag: isXss ? "XSS" : null
                };

                if (isXss) {
                    const xssIssue = {
                        id: `issue_${runtimeId()}`,
                        engine: "RUNTIME",
                        type: "XSS",
                        severity: "HIGH",
                        confidence: "HIGH",
                        context: "ATTR",
                        sink: m.attributeName,
                        detail: `javascript: URL set on ${m.attributeName} attribute of <${m.target.tagName.toLowerCase()}>`,
                        value: val.substring(0, 80),
                        recommendation: `Never assign user-controlled values to ${m.attributeName}. Validate that URLs begin with https:// before assignment.`,
                        timestamp: Date.now()
                    };
                    currentReport.issues.push(xssIssue);
                    refreshSecurityScore();
                    console.log("PixelSpy: XSS issue created from DOM mutation", xssIssue);
                }

                currentReport.events.push(event);
                trimEvents();
            }

            // ── Added nodes ───────────────────────────────────────────────────
            m.addedNodes.forEach(node => {
                if (node.nodeType !== 1) return;

                let flag = null;

                // Dynamically injected <script> tags are a strong XSS signal
                if (node.tagName === "SCRIPT" && !node.src) {
                    flag = "XSS";
                    const scriptIssue = {
                        id: `issue_${runtimeId()}`,
                        engine: "RUNTIME",
                        type: "XSS",
                        severity: "CRITICAL",
                        confidence: "MEDIUM",
                        context: "JS",
                        sink: "script injection",
                        detail: "Dynamic inline <script> element injected into the DOM at runtime",
                        recommendation: "Avoid injecting raw script elements from user data. Use a strict CSP with nonces.",
                        timestamp: Date.now()
                    };
                    currentReport.issues.push(scriptIssue);
                    refreshSecurityScore();
                }

                const event = {
                    type: "DOM",
                    detail: `node added: <${node.tagName ? node.tagName.toLowerCase() : "?"}>`,
                    timestamp: Date.now(),
                    flag
                };
                currentReport.events.push(event);
                trimEvents();
            });
        });
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["src", "href", "action"]
    });
})();

// ── Message Listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    console.log("PixelSpy: Received message", msg.action);

    if (msg.action === "GET_REPORT") {
        console.log("PixelSpy: Sending report with", currentReport.issues.length, "issues and", currentReport.events.length, "events");
        sendResponse({ success: true, report: currentReport });
    }

    if (msg.action === "RUN_SCAN") {
        console.log("PixelSpy: Running scan...");

        // Preserve runtime-detected issues, only clear AST issues for re-scan
        const runtimeIssues = currentReport.issues.filter(i => i.engine === "RUNTIME");
        currentReport.issues = runtimeIssues;
        currentReport.events = [];
        currentReport.scanTime = Date.now();
        currentReport.url = location.href;

        // Static analysis
        try {
            if (typeof window.runStaticAnalysis === "function") {
                const astIssues = window.runStaticAnalysis();
                console.log("PixelSpy: Static analysis found", astIssues.length, "issues");
                currentReport.issues.push(...astIssues);
            }
        } catch (e) {
            console.error("PixelSpy: Static analysis failed", e);
            currentReport.issues.push({
                id: `issue_${runtimeId()}`,
                type: "ERROR",
                severity: "INFO",
                engine: "AST",
                detail: "Static analysis failed: " + e.message
            });
        }

        // Attack surface mapping
        try {
            if (typeof window.mapAttackSurface === "function") {
                currentReport.attackSurface = window.mapAttackSurface();
                console.log("PixelSpy: Attack surface mapped",
                    currentReport.attackSurface.metadata.inputVectorCount, "input vectors");
            }
        } catch (e) {
            console.error("PixelSpy: Attack surface mapping failed", e);
        }

        // Security scoring
        refreshSecurityScore();

        console.log("PixelSpy: Final report has", currentReport.issues.length, "issues");
        sendResponse({ success: true, report: currentReport });
    }

    return true; // keep message channel open for async sendResponse
});

console.log("PixelSpy: content.js loaded in ISOLATED world ✓");
