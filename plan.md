# PixelSpy DevTools Extension
## Complete Agentic Build Architecture

> **Purpose of this document:** This file is the single source of truth for building the PixelSpy Chrome DevTools extension end-to-end. An AI agent reading this document should be able to produce every file, every function, every line of CSS, and every message handler with zero ambiguity. Nothing is left to inference.

---

## 0. Project Identity


**What the project is:**

PixelSpy is a Chrome DevTools extension that sits inside your browser's developer tools and acts like a lightweight security scanner for whatever web page you're currently on. Instead of running an external tool against a deployed app, you just open DevTools, hit Scan, and it analyzes the page from the inside — reading the actual JavaScript, watching network requests in real time, and flagging potential vulnerabilities directly in the panel. It's positioned as a learning project, meaning the goal isn't to replace Burp Suite or OWASP ZAP — it's to understand *how* these tools work by building one yourself.

---

**What it contains:**

The extension is split across two execution contexts that can't directly talk to each other — the page itself, and the DevTools panel — which is why there's a background service worker acting as a message broker between them. On the page side, two scripts run as content scripts: `staticEngine.js` which parses the page's JavaScript into an AST and walks it looking for dangerous data flows, and `content.js` which hooks into the browser's native `fetch` and `XMLHttpRequest` APIs to watch network traffic in real time. On the DevTools side, `panel.html/css/js` renders the UI — an issue explorer on the left, a detail pane on the right, and a live event stream at the bottom. `background.js` sits in between and routes messages whenever the panel wants to trigger a scan or fetch the latest report.

---

**Features:**

The AST-based static analyzer is the centrepiece. It loads Acorn (a JavaScript parser) to convert inline script tags into an ESTree-format syntax tree, then walks every node looking for assignments where a user-controlled value — `location.search`, `document.cookie`, `localStorage.getItem` — gets stored into a variable. From that point, it tracks that variable through subsequent assignments (taint propagation), and if that tainted variable eventually reaches a dangerous sink like `innerHTML`, `eval`, or `document.write` without passing through a known sanitizer like `DOMPurify`, it fires an XSS issue. The context of the sink matters too — injecting into `eval()` is flagged Critical, while injecting into `innerHTML` is High, because the execution risk is different.

The runtime analyzer runs in parallel. It monkey-patches `window.fetch` and `XMLHttpRequest.prototype.open` so every outbound network request passes through inspection before it leaves. Each URL gets scored by the SQLi heuristic engine — if the URL contains SQL keywords in its parameter values, or has parameter names like `id`, `user`, `query`, `search` that are commonly exploited, or carries numeric values that match injection patterns, it accumulates points. Sixty-plus points triggers a Medium confidence SQLi flag, seventy-plus triggers High. The MutationObserver watches DOM changes simultaneously — if an attribute like `src` or `href` gets set to a `javascript:` URL, that's flagged as XSS too.

The panel UI has three zones. The issue explorer lists every detected vulnerability with a severity badge (Critical/High/Medium/Low) and a colored dot indicating type (purple for XSS, green for SQLi). Clicking any issue loads the detail pane, which for XSS shows a visual flow trace — a chain of three nodes labeled SRC → VAR → SNK — showing exactly which source fed which variable which then reached which sink, with line numbers. For SQLi it shows the full URL, the request method, the confidence score, and the specific evidence signals that triggered it. The event stream at the bottom is a live table of every fetch, XHR, and DOM mutation happening on the page, auto-updating every three seconds via polling.

---

**The logical concepts at work:**

Taint analysis is the core CS concept. It's the same foundational technique used in production-grade SAST tools like CodeQL and Semgrep — the idea that data originating from an untrusted source is "tainted," and if that taint reaches a sensitive operation without being sanitized, you have a vulnerability. The implementation here is intra-function only, meaning it tracks taint within a single function's scope rather than following it across function call boundaries, which keeps the complexity manageable without losing the conceptual integrity.

The messaging architecture teaches a real constraint of browser extensions — content scripts, DevTools panels, and background workers are isolated JavaScript contexts with no shared memory. Every piece of data that crosses a boundary has to be serialized through Chrome's `runtime.sendMessage` API. The background service worker acts purely as a stateless relay — it receives a message from the panel, forwards it to the content script, and passes the response back. This is the same pub/sub pattern used in microservice architectures, just expressed through browser extension APIs.

Monkey-patching the fetch prototype is an instrumentation technique — you save a reference to the original function, replace it with your own wrapper, do your inspection, then call the original so the page continues working normally. This is how APM agents, mock libraries, and test frameworks intercept network calls without modifying application code.

The SQLi scorer is a layered heuristic model — no single signal is enough to confirm an injection point, but multiple weak signals combined push the confidence score over a threshold. This is how most real-world anomaly detection works: not one definitive proof, but an accumulation of evidence that crosses a decision boundary.


| Field | Value |
|---|---|
| Project name | PixelSpy DevTools Extension |
| Type | Chrome Extension (Manifest V3) |
| Purpose | Learning-focused frontend security analyzer |
| Target | Developers auditing their own web apps |
| Testing targets | DVWA, OWASP Juice Shop |
| Doability | 93% |



---

## 1. Absolute Constraints

These rules are non-negotiable. Every generated file must respect them.

1. **Manifest V3 only.** No `background.persistent`. Use service workers.
2. **Zero frontend frameworks.** Panel UI is plain HTML + CSS + vanilla JS. No React, no Vue, no build step.
3. **Zero external CDN calls from the extension.** Acorn is bundled locally. No runtime fetches to unpkg/jsdelivr from content scripts.
4. **No cross-origin request injection.** The SQLi engine only inspects requests — it never clones and re-sends them to avoid CORS violations.
5. **Intra-function taint tracking only.** The AST engine does not build call graphs. It tracks variable taint within a single function scope.
6. **All files live under `extension/`.** The agent must generate every file inside this directory.

---

## 2. Complete File Tree

The agent must generate every file listed here. Files marked `[BUNDLE]` require bundling acorn into the extension.

```
extension/
├── manifest.json
├── content.js
├── staticEngine.js
├── acorn.min.js                  ← [BUNDLE] download from npm acorn, minified
├── background.js
├── devtools/
│   ├── devtools.html
│   └── devtools.js
├── panel/
│   ├── panel.html
│   ├── panel.css
│   └── panel.js
└── icons/
    ├── icon16.png                ← plain indigo square, agent may use placeholder
    ├── icon48.png
    └── icon128.png
```

---

## 3. manifest.json — Complete Spec

```json
{
  "manifest_version": 3,
  "name": "PixelSpy",
  "version": "1.0.0",
  "description": "Runtime + static vulnerability analyzer for frontend security.",

  "permissions": [
    "activeTab",
    "scripting",
    "storage",
    "tabs"
  ],

  "host_permissions": [
    "<all_urls>"
  ],

  "background": {
    "service_worker": "background.js"
  },

  "devtools_page": "devtools/devtools.html",

  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["acorn.min.js", "staticEngine.js", "content.js"],
      "run_at": "document_idle",
      "all_frames": false
    }
  ],

  "icons": {
    "16":  "icons/icon16.png",
    "48":  "icons/icon48.png",
    "128": "icons/icon128.png"
  },

  "action": {
    "default_icon": "icons/icon48.png",
    "default_title": "PixelSpy"
  }
}
```

**Constraint notes for agent:**
- `"run_at": "document_idle"` ensures the DOM is ready before content scripts run.
- `acorn.min.js` must load before `staticEngine.js` in the content scripts array.
- No `"web_accessible_resources"` needed for this build.

---

## 4. acorn.min.js — Bundling Instruction

The agent must produce a bundled `acorn.min.js` by taking the UMD build of acorn v8.x.

**Source:** `node_modules/acorn/dist/acorn.js` after `npm install acorn`

**Required global:** The file must expose `window.acorn` (or `self.acorn` for service worker context). The UMD build does this automatically.

**Minimum required API surface used by staticEngine.js:**
```javascript
acorn.parse(code, { ecmaVersion: 2020, sourceType: "script", tolerant: true })
// returns: ESTree-compliant AST object
```

**If the agent cannot bundle acorn, it must use this inline stub** that parses enough to detect the patterns we care about — but the real acorn bundle is strongly preferred:
```javascript
// STUB — only use if acorn bundle is unavailable
window.acorn = {
  parse: function(code) {
    // Return minimal AST shell so staticEngine.js doesn't crash
    return { type: "Program", body: [] };
  }
};
```

---

## 5. staticEngine.js — Complete Spec

**Role:** Loaded as a content script. Exposes one global function `runStaticAnalysis()` that returns an array of issue objects.

**Dependencies:** `window.acorn` (loaded before this file via manifest content_scripts order)

### 5.1 Constants

```javascript
const SOURCES = [
  "location.search",
  "location.hash",
  "document.cookie",
  "localStorage.getItem",
  "sessionStorage.getItem",
  "document.referrer",
  "window.name"
];

const SINKS = {
  "innerHTML":        { severity: "HIGH",     context: "HTML" },
  "outerHTML":        { severity: "HIGH",     context: "HTML" },
  "insertAdjacentHTML": { severity: "HIGH",   context: "HTML" },
  "eval":             { severity: "CRITICAL", context: "JS"   },
  "setTimeout":       { severity: "HIGH",     context: "JS"   },
  "setInterval":      { severity: "HIGH",     context: "JS"   },
  "document.write":   { severity: "HIGH",     context: "HTML" },
  "document.writeln": { severity: "HIGH",     context: "HTML" },
  "src":              { severity: "MEDIUM",   context: "ATTR" },
  "href":             { severity: "MEDIUM",   context: "URL"  }
};

const SANITIZERS = [
  "DOMPurify.sanitize",
  "encodeURIComponent",
  "encodeURI",
  "escape",
  "htmlspecialchars",
  "sanitize"
];

const SQLI_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
                        "WHERE", "FROM", "TABLE", "--", "OR 1=1", "' OR '"];

const SQLI_PARAM_NAMES = ["id", "user", "username", "query", "search",
                           "filter", "sort", "order", "category", "type"];
```

### 5.2 Main Export Function

```javascript
window.runStaticAnalysis = function() {
  const issues = [];
  const scripts = extractScripts();

  scripts.forEach((src, idx) => {
    try {
      const ast = acorn.parse(src, {
        ecmaVersion: 2020,
        sourceType: "script",
        locations: true,
        tolerant: true
      });
      const fileIssues = analyzeAST(ast, src, `inline-script-${idx}`);
      issues.push(...fileIssues);
    } catch (e) {
      // Parse error — skip this script block silently
    }
  });

  return issues;
};
```

### 5.3 Script Extraction

```javascript
function extractScripts() {
  const scripts = [];
  document.querySelectorAll("script:not([src])").forEach(el => {
    if (el.textContent.trim().length > 0) {
      scripts.push(el.textContent);
    }
  });
  return scripts;
}
```

### 5.4 AST Analyzer

```javascript
function analyzeAST(ast, src, fileLabel) {
  const issues = [];
  // taintedVars: Map<string, { source: string, line: number }>
  const taintedVars = new Map();

  function walk(node, parent) {
    if (!node || typeof node !== "object") return;

    // --- TAINT ASSIGNMENT DETECTION ---
    // Pattern: varName = location.search  OR  varName = document.cookie  etc.
    if (node.type === "AssignmentExpression" || node.type === "VariableDeclarator") {
      const left  = node.type === "AssignmentExpression" ? node.left  : node.id;
      const right = node.type === "AssignmentExpression" ? node.right : node.init;

      if (left && right) {
        const sourceMatch = matchesSource(right);
        if (sourceMatch) {
          const varName = extractName(left);
          if (varName) {
            taintedVars.set(varName, {
              source: sourceMatch,
              line: node.loc ? node.loc.start.line : 0
            });
          }
        }

        // Propagate taint: if right side uses a tainted var, left side becomes tainted too
        const usedVars = collectIdentifiers(right);
        usedVars.forEach(v => {
          if (taintedVars.has(v)) {
            const varName = extractName(left);
            if (varName && !taintedVars.has(varName)) {
              taintedVars.set(varName, {
                source: taintedVars.get(v).source + " (propagated)",
                line: node.loc ? node.loc.start.line : 0
              });
            }
          }
        });
      }
    }

    // --- SINK DETECTION ---
    // Pattern: element.innerHTML = taintedVar
    if (node.type === "AssignmentExpression") {
      const sinkName = extractSinkName(node.left);
      if (sinkName && SINKS[sinkName]) {
        const usedVars = collectIdentifiers(node.right);
        usedVars.forEach(v => {
          if (taintedVars.has(v)) {
            const taintInfo = taintedVars.get(v);
            const sinkInfo  = SINKS[sinkName];

            if (!hasSanitizer(node.right)) {
              issues.push(buildIssue({
                type:       "XSS",
                severity:   sinkInfo.severity,
                context:    sinkInfo.context,
                source:     taintInfo.source,
                variable:   v,
                sink:       sinkName,
                sourceLine: taintInfo.line,
                sinkLine:   node.loc ? node.loc.start.line : 0,
                sanitized:  false,
                file:       fileLabel,
                confidence: "HIGH"
              }));
            }
          }
        });
      }
    }

    // Pattern: eval(taintedVar)  or  setTimeout(taintedVar, ...)
    if (node.type === "CallExpression") {
      const calleeName = extractCalleeName(node.callee);
      if (calleeName && SINKS[calleeName]) {
        const args = node.arguments || [];
        args.forEach(arg => {
          const usedVars = collectIdentifiers(arg);
          usedVars.forEach(v => {
            if (taintedVars.has(v)) {
              const taintInfo = taintedVars.get(v);
              const sinkInfo  = SINKS[calleeName];

              issues.push(buildIssue({
                type:       "XSS",
                severity:   sinkInfo.severity,
                context:    sinkInfo.context,
                source:     taintInfo.source,
                variable:   v,
                sink:       calleeName + "()",
                sourceLine: taintInfo.line,
                sinkLine:   node.loc ? node.loc.start.line : 0,
                sanitized:  false,
                file:       fileLabel,
                confidence: "HIGH"
              }));
            }
          });
        });
      }
    }

    // --- RECURSE ---
    for (const key of Object.keys(node)) {
      if (key === "type" || key === "loc" || key === "start" || key === "end") continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => walk(c, node));
      } else if (child && typeof child === "object" && child.type) {
        walk(child, node);
      }
    }
  }

  walk(ast, null);
  return issues;
}
```

### 5.5 Helper Functions

```javascript
// Returns the SOURCE string if node matches a known taint source, else null
function matchesSource(node) {
  if (!node) return null;

  // location.search, document.cookie, etc.
  if (node.type === "MemberExpression") {
    const str = memberExprToString(node);
    for (const src of SOURCES) {
      if (str === src || str.startsWith(src)) return src;
    }
  }

  // localStorage.getItem(...)
  if (node.type === "CallExpression") {
    const str = memberExprToString(node.callee);
    for (const src of SOURCES) {
      if (str === src || str.startsWith(src)) return src;
    }
  }

  return null;
}

// Converts MemberExpression AST node to "object.property" string
function memberExprToString(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    return memberExprToString(node.object) + "." + memberExprToString(node.property);
  }
  return "";
}

// Returns variable name string from left-hand side of assignment
function extractName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  return null;
}

// Extracts sink property name from left side of assignment (e.g. el.innerHTML -> "innerHTML")
function extractSinkName(node) {
  if (!node) return null;
  if (node.type === "MemberExpression" && node.property) {
    const prop = node.property.name || node.property.value;
    if (prop && SINKS[prop]) return prop;
  }
  return null;
}

// Extracts callee name from CallExpression.callee
function extractCalleeName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    return node.property ? (node.property.name || null) : null;
  }
  return null;
}

// Recursively collect all Identifier names used in an expression
function collectIdentifiers(node) {
  const names = new Set();
  function visit(n) {
    if (!n || typeof n !== "object") return;
    if (n.type === "Identifier") { names.add(n.name); return; }
    for (const k of Object.keys(n)) {
      const c = n[k];
      if (Array.isArray(c)) c.forEach(visit);
      else if (c && typeof c === "object" && c.type) visit(c);
    }
  }
  visit(node);
  return names;
}

// Returns true if the expression contains a known sanitizer call
function hasSanitizer(node) {
  let found = false;
  function visit(n) {
    if (!n || typeof n !== "object" || found) return;
    if (n.type === "CallExpression") {
      const name = memberExprToString(n.callee);
      if (SANITIZERS.some(s => name.includes(s))) { found = true; return; }
    }
    for (const k of Object.keys(n)) {
      const c = n[k];
      if (Array.isArray(c)) c.forEach(visit);
      else if (c && typeof c === "object" && c.type) visit(c);
    }
  }
  visit(node);
  return found;
}

// Generates a unique ID for each issue
let _issueCounter = 0;
function buildIssue(fields) {
  return {
    id:         `issue_${String(++_issueCounter).padStart(3, "0")}`,
    engine:     "AST",
    timestamp:  Date.now(),
    ...fields
  };
}
```

### 5.6 SQLi Heuristic Scorer (used by content.js, exported from staticEngine.js)

```javascript
window.scoreRequestForSQLi = function(url, method) {
  let score = 0;
  const evidence = [];

  try {
    const parsed = new URL(url);
    const params = [...parsed.searchParams.entries()];

    params.forEach(([key, value]) => {
      // Layer 1: SQL keyword presence in value
      const upperVal = value.toUpperCase();
      SQLI_KEYWORDS.forEach(kw => {
        if (upperVal.includes(kw)) {
          score += 30;
          evidence.push(`keyword "${kw}" in param "${key}"`);
        }
      });

      // Layer 2a: Suspicious parameter name
      if (SQLI_PARAM_NAMES.includes(key.toLowerCase())) {
        score += 25;
        evidence.push(`suspicious param name: "${key}"`);
      }

      // Layer 2b: Numeric value (common in id-based injection)
      if (/^\d+$/.test(value)) {
        score += 15;
        evidence.push(`numeric value in param "${key}"`);
      }
    });
  } catch (e) {
    return null;
  }

  if (score === 0) return null;

  return {
    id:         `issue_${String(++_issueCounter).padStart(3, "0")}`,
    engine:     "RUNTIME",
    type:       "SQLi",
    url,
    method:     method || "GET",
    score,
    confidence: score >= 70 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW",
    severity:   score >= 70 ? "HIGH" : "MEDIUM",
    evidence,
    timestamp:  Date.now()
  };
};
```

---

## 6. content.js — Complete Spec

**Role:** Content script. Orchestrates runtime hooks, feeds the static engine, maintains `currentReport`, responds to messages from the background service worker.

### 6.1 State

```javascript
let currentReport = {
  url:      location.href,
  scanTime: null,
  issues:   [],         // array of issue objects from both engines
  events:   []          // array of runtime events (fetch, XHR, DOM mutations)
};
```

### 6.2 fetch Hook

```javascript
(function hookFetch() {
  const _fetch = window.fetch;
  window.fetch = async function(...args) {
    const url    = typeof args[0] === "string" ? args[0] : args[0]?.url || "";
    const method = (args[1]?.method || "GET").toUpperCase();

    const event = {
      type:      "FETCH",
      url,
      method,
      timestamp: Date.now(),
      flag:      null
    };

    const sqliResult = window.scoreRequestForSQLi(url, method);
    if (sqliResult) {
      event.flag = "SQLi";
      currentReport.issues.push(sqliResult);
    }

    currentReport.events.push(event);
    trimEvents();

    return _fetch.apply(this, args);
  };
})();
```

### 6.3 XHR Hook

```javascript
(function hookXHR() {
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    const event = {
      type:      "XHR",
      url:       url || "",
      method:    (method || "GET").toUpperCase(),
      timestamp: Date.now(),
      flag:      null
    };

    const sqliResult = window.scoreRequestForSQLi(url, method);
    if (sqliResult) {
      event.flag = "SQLi";
      currentReport.issues.push(sqliResult);
    }

    currentReport.events.push(event);
    trimEvents();

    return _open.apply(this, [method, url, ...rest]);
  };
})();
```

### 6.4 MutationObserver

```javascript
(function hookDOM() {
  const observer = new MutationObserver(mutations => {
    mutations.forEach(m => {
      if (m.type === "attributes" &&
          (m.attributeName === "src" || m.attributeName === "href")) {
        const val = m.target.getAttribute(m.attributeName) || "";
        const event = {
          type:      "DOM",
          detail:    `${m.attributeName} changed on <${m.target.tagName.toLowerCase()}>`,
          value:     val.substring(0, 80),
          timestamp: Date.now(),
          flag:      val.toLowerCase().startsWith("javascript:") ? "XSS" : null
        };
        currentReport.events.push(event);
        trimEvents();
      }

      m.addedNodes.forEach(node => {
        if (node.nodeType !== 1) return;
        const event = {
          type:      "DOM",
          detail:    `node added: <${node.tagName ? node.tagName.toLowerCase() : "?"}>`,
          timestamp: Date.now(),
          flag:      null
        };
        currentReport.events.push(event);
        trimEvents();
      });
    });
  });

  observer.observe(document.documentElement, {
    childList:  true,
    subtree:    true,
    attributes: true,
    attributeFilter: ["src", "href", "innerHTML", "action"]
  });
})();
```

### 6.5 Utility

```javascript
// Keep events array bounded to avoid memory growth
function trimEvents() {
  if (currentReport.events.length > 200) {
    currentReport.events = currentReport.events.slice(-200);
  }
}
```

### 6.6 Message Listener

```javascript
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "GET_REPORT") {
    sendResponse({ success: true, report: currentReport });
  }

  if (msg.action === "RUN_SCAN") {
    currentReport.issues   = [];
    currentReport.events   = [];
    currentReport.scanTime = Date.now();
    currentReport.url      = location.href;

    try {
      const astIssues = window.runStaticAnalysis();
      currentReport.issues.push(...astIssues);
    } catch (e) {
      currentReport.issues.push({
        id:       "err_001",
        type:     "ERROR",
        severity: "INFO",
        detail:   "Static analysis failed: " + e.message
      });
    }

    sendResponse({ success: true, report: currentReport });
  }

  return true; // keep message channel open for async sendResponse
});
```

---

## 7. background.js — Complete Spec

**Role:** MV3 service worker. Acts as the messaging bridge between the DevTools panel and the content script. The panel cannot access tabs directly — all messages route through here.

```javascript
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Panel asking for report or triggering scan
  if (msg.action === "GET_REPORT" || msg.action === "RUN_SCAN") {
    // Find the inspected tab (passed in by panel.js as msg.tabId)
    const tabId = msg.tabId;
    if (!tabId) {
      sendResponse({ success: false, error: "No tabId provided" });
      return true;
    }

    chrome.tabs.sendMessage(tabId, { action: msg.action }, (response) => {
      if (chrome.runtime.lastError) {
        sendResponse({
          success: false,
          error:   chrome.runtime.lastError.message
        });
      } else {
        sendResponse(response);
      }
    });

    return true; // async
  }
});
```

---

## 8. devtools/devtools.html — Complete Spec

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script src="devtools.js"></script>
</body>
</html>
```

---

## 9. devtools/devtools.js — Complete Spec

```javascript
chrome.devtools.panels.create(
  "PixelSpy",
  "",
  "../panel/panel.html",
  function(panel) {
    // Panel created — no additional setup needed
  }
);
```

---

## 10. panel/panel.html — Complete Spec

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PixelSpy</title>
  <link rel="stylesheet" href="panel.css">
</head>
<body>

  <!-- TOOLBAR -->
  <header class="toolbar">
    <div class="toolbar-left">
      <span class="logo">PixelSpy</span>
      <button class="btn btn-primary" id="btn-scan">Scan</button>
      <button class="btn btn-ghost" id="btn-clear">Clear</button>
    </div>
    <div class="toolbar-right">
      <div class="filter-group" id="filter-type">
        <button class="filter-btn active" data-filter="ALL">All</button>
        <button class="filter-btn" data-filter="XSS">XSS</button>
        <button class="filter-btn" data-filter="SQLi">SQLi</button>
      </div>
      <div class="filter-group" id="filter-severity">
        <button class="filter-btn active" data-sev="ALL">All Severity</button>
        <button class="filter-btn" data-sev="CRITICAL">Critical</button>
        <button class="filter-btn" data-sev="HIGH">High</button>
        <button class="filter-btn" data-sev="MEDIUM">Medium</button>
      </div>
    </div>
  </header>

  <!-- STATUS BAR -->
  <div class="status-bar" id="status-bar">
    <span id="status-text">Ready — click Scan to analyze the current page.</span>
    <span id="issue-count" class="issue-count hidden"></span>
  </div>

  <!-- MAIN SPLIT VIEW -->
  <div class="main-layout">

    <!-- LEFT PANE: Issue Explorer -->
    <aside class="issue-explorer" id="issue-explorer">
      <div class="pane-header">Issues</div>
      <div class="issue-list" id="issue-list">
        <div class="empty-state" id="empty-state">
          No issues found. Run a scan.
        </div>
      </div>
    </aside>

    <!-- RIGHT PANE: Detail Panel -->
    <section class="detail-panel" id="detail-panel">
      <div class="pane-header">Detail</div>
      <div class="detail-content" id="detail-content">
        <div class="empty-state">Select an issue to view details.</div>
      </div>
    </section>

  </div>

  <!-- BOTTOM STRIP: Event Stream -->
  <footer class="event-stream">
    <div class="pane-header">
      Live Events
      <span class="event-count" id="event-count">0</span>
    </div>
    <div class="event-table-wrap">
      <table class="event-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>URL / Detail</th>
            <th>Flag</th>
          </tr>
        </thead>
        <tbody id="event-tbody"></tbody>
      </table>
    </div>
  </footer>

  <script src="panel.js"></script>
</body>
</html>
```

---

## 11. panel/panel.css — Complete Spec

This is the complete stylesheet. The agent must generate exactly this file without modification.

```css
/* ── Design tokens ── */
:root {
  --bg-base:      #0b0f1a;
  --bg-surface:   #111827;
  --bg-elevated:  #1a2236;
  --bg-hover:     #1e2d45;
  --bg-selected:  #1e3a5f;

  --border:       #1e2d45;
  --border-light: #2a3a55;

  --text-primary:   #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted:     #475569;
  --text-code:      #7dd3fc;

  --accent:       #4f8ef7;
  --accent-dim:   #1e3a5f;

  --sev-critical: #f87171;
  --sev-high:     #fb923c;
  --sev-medium:   #fbbf24;
  --sev-low:      #60a5fa;
  --sev-info:     #94a3b8;

  --type-xss:     #a78bfa;
  --type-sqli:    #34d399;
  --type-error:   #94a3b8;

  --font-ui:   "Segoe UI", system-ui, -apple-system, sans-serif;
  --font-mono: "Cascadia Code", "Fira Code", "Consolas", monospace;

  --radius-sm: 3px;
  --radius-md: 6px;
  --radius-lg: 8px;
}

/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  height: 100%;
  width: 100%;
  overflow: hidden;
  background: var(--bg-base);
  color: var(--text-primary);
  font-family: var(--font-ui);
  font-size: 12px;
  line-height: 1.5;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-light); border-radius: 3px; }

/* ── Toolbar ── */
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 36px;
  padding: 0 10px;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  gap: 8px;
}

.toolbar-left, .toolbar-right {
  display: flex;
  align-items: center;
  gap: 6px;
}

.logo {
  font-size: 12px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.06em;
  margin-right: 4px;
  text-transform: uppercase;
}

/* ── Buttons ── */
.btn {
  height: 24px;
  padding: 0 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-light);
  font-family: var(--font-ui);
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.12s, border-color 0.12s;
  white-space: nowrap;
}

.btn-primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.btn-primary:hover  { background: #3b7de8; }
.btn-primary:active { transform: scale(0.97); }

.btn-ghost {
  background: transparent;
  color: var(--text-secondary);
}
.btn-ghost:hover { background: var(--bg-elevated); color: var(--text-primary); }

/* ── Filter pills ── */
.filter-group {
  display: flex;
  gap: 2px;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 2px;
}

.filter-btn {
  height: 20px;
  padding: 0 8px;
  border: none;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-secondary);
  font-size: 11px;
  font-family: var(--font-ui);
  cursor: pointer;
  transition: background 0.1s, color 0.1s;
}
.filter-btn:hover  { background: var(--bg-elevated); color: var(--text-primary); }
.filter-btn.active { background: var(--accent); color: #fff; }

/* ── Status bar ── */
.status-bar {
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

#status-text { font-size: 11px; color: var(--text-secondary); }

.issue-count {
  font-size: 11px;
  font-weight: 600;
  color: var(--sev-high);
}
.issue-count.hidden { display: none; }

/* ── Layout ── */
body {
  display: flex;
  flex-direction: column;
}

.main-layout {
  flex: 1;
  display: flex;
  overflow: hidden;
  min-height: 0;
}

.issue-explorer {
  width: 260px;
  min-width: 200px;
  flex-shrink: 0;
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.detail-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ── Pane headers ── */
.pane-header {
  height: 28px;
  display: flex;
  align-items: center;
  padding: 0 10px;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  gap: 6px;
}

/* ── Issue list ── */
.issue-list {
  flex: 1;
  overflow-y: auto;
}

.issue-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 7px 10px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.1s;
}
.issue-row:hover    { background: var(--bg-hover); }
.issue-row.selected { background: var(--bg-selected); }

.issue-left {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  flex-shrink: 0;
  padding-top: 1px;
}

.type-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.type-dot.xss   { background: var(--type-xss);  }
.type-dot.sqli  { background: var(--type-sqli); }
.type-dot.error { background: var(--type-error);}

.sev-badge {
  font-size: 9px;
  font-weight: 700;
  padding: 1px 4px;
  border-radius: 2px;
  letter-spacing: 0.04em;
}
.sev-badge.critical { background: #3b0a0a; color: var(--sev-critical); }
.sev-badge.high     { background: #3b1a0a; color: var(--sev-high);     }
.sev-badge.medium   { background: #3b2a0a; color: var(--sev-medium);   }
.sev-badge.low      { background: #0a1a3b; color: var(--sev-low);      }

.issue-body { flex: 1; min-width: 0; }
.issue-title {
  font-size: 11px;
  font-weight: 500;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.issue-sub {
  font-size: 10px;
  color: var(--text-muted);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ── Detail panel ── */
.detail-content {
  flex: 1;
  overflow-y: auto;
  padding: 14px 16px;
}

/* Summary block */
.detail-summary {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 16px;
}

.detail-stat {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 8px 10px;
}
.detail-stat-label {
  font-size: 10px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 3px;
}
.detail-stat-value {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

/* Flow trace */
.flow-trace {
  margin-bottom: 16px;
}

.flow-trace-title {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  margin-bottom: 8px;
}

.flow-chain {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.flow-node {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 0;
  position: relative;
}
.flow-node:first-child { border-radius: var(--radius-md) var(--radius-md) 0 0; }
.flow-node:last-child  { border-radius: 0 0 var(--radius-md) var(--radius-md); }
.flow-node:only-child  { border-radius: var(--radius-md); }
.flow-node + .flow-node { border-top: none; }

.flow-node-icon {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 700;
  flex-shrink: 0;
}
.flow-node-icon.source { background: #1a3a2a; color: var(--type-sqli); }
.flow-node-icon.var    { background: #1a1a3a; color: var(--accent);    }
.flow-node-icon.sink   { background: #3a1a1a; color: var(--sev-high);  }

.flow-node-label {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-code);
}
.flow-node-meta {
  font-size: 10px;
  color: var(--text-muted);
  margin-left: auto;
}

.flow-connector {
  width: 1px;
  height: 10px;
  background: var(--border-light);
  margin-left: 19px;
}

/* Context block */
.context-block {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 10px 12px;
  margin-bottom: 12px;
}

.context-block-title {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  margin-bottom: 8px;
}

.context-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 3px 0;
  border-bottom: 1px solid var(--border);
}
.context-row:last-child { border-bottom: none; }
.context-key   { font-size: 11px; color: var(--text-secondary); }
.context-value { font-size: 11px; font-weight: 500; color: var(--text-primary); }

/* SQLi evidence block */
.evidence-block {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 10px 12px;
  margin-bottom: 12px;
}
.evidence-item {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 3px 0;
  font-size: 11px;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--border);
}
.evidence-item:last-child { border-bottom: none; }
.evidence-bullet {
  color: var(--sev-medium);
  flex-shrink: 0;
  margin-top: 1px;
}

/* Empty state */
.empty-state {
  padding: 24px 16px;
  text-align: center;
  font-size: 11px;
  color: var(--text-muted);
}

/* ── Event stream ── */
.event-stream {
  height: 140px;
  min-height: 100px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}

.event-count {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1px 6px;
  font-size: 10px;
  color: var(--text-secondary);
}

.event-table-wrap {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
}

.event-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
}

.event-table thead th {
  position: sticky;
  top: 0;
  background: var(--bg-surface);
  color: var(--text-muted);
  text-align: left;
  font-weight: 600;
  font-size: 10px;
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.event-table tbody tr {
  border-bottom: 1px solid var(--border);
  transition: background 0.1s;
}
.event-table tbody tr:hover { background: var(--bg-hover); }

.event-table tbody td {
  padding: 4px 8px;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 300px;
}

.event-table tbody td:first-child { color: var(--text-muted); width: 60px; }
.event-table tbody td:nth-child(2) { width: 50px; font-weight: 500; }
.event-table tbody td:last-child   { width: 50px; }

.event-flag {
  display: inline-block;
  padding: 1px 5px;
  border-radius: 2px;
  font-size: 9px;
  font-weight: 700;
}
.event-flag.xss  { background: #2a1a3a; color: var(--type-xss);  }
.event-flag.sqli { background: #0a2a1a; color: var(--type-sqli); }

/* ── Scan animation ── */
@keyframes pulse-text {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.5; }
}
.scanning { animation: pulse-text 1s ease-in-out infinite; }
```

---

## 12. panel/panel.js — Complete Spec

**Role:** All panel UI logic. Requests reports from content.js via background.js, renders issue list, renders detail view, renders event stream. Handles filters.

### 12.1 State

```javascript
let allIssues  = [];
let allEvents  = [];
let activeTypeFilter = "ALL";
let activeSevFilter  = "ALL";
let selectedIssueId  = null;
let pollInterval     = null;
```

### 12.2 Initialisation

```javascript
document.addEventListener("DOMContentLoaded", () => {
  bindToolbar();
  bindFilters();
  startEventPoll();
});
```

### 12.3 Toolbar Bindings

```javascript
function bindToolbar() {
  document.getElementById("btn-scan").addEventListener("click", runScan);
  document.getElementById("btn-clear").addEventListener("click", clearAll);
}

function runScan() {
  setStatus("Scanning...", true);
  sendToContent("RUN_SCAN", (response) => {
    if (!response || !response.success) {
      setStatus("Scan failed — is the page fully loaded?", false);
      return;
    }
    allIssues = response.report.issues || [];
    allEvents = response.report.events || [];
    renderIssueList();
    renderEventStream();

    const count = allIssues.length;
    setStatus(
      `Scan complete — ${count} issue${count !== 1 ? "s" : ""} found.`,
      false,
      count
    );
  });
}

function clearAll() {
  allIssues = [];
  allEvents = [];
  selectedIssueId = null;
  renderIssueList();
  renderEventStream();
  renderDetail(null);
  setStatus("Cleared.", false, 0);
  document.getElementById("issue-count").classList.add("hidden");
}
```

### 12.4 Filter Bindings

```javascript
function bindFilters() {
  document.getElementById("filter-type").addEventListener("click", e => {
    const btn = e.target.closest(".filter-btn");
    if (!btn) return;
    document.querySelectorAll("#filter-type .filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeTypeFilter = btn.dataset.filter;
    renderIssueList();
  });

  document.getElementById("filter-severity").addEventListener("click", e => {
    const btn = e.target.closest(".filter-btn");
    if (!btn) return;
    document.querySelectorAll("#filter-severity .filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeSevFilter = btn.dataset.sev;
    renderIssueList();
  });
}

function getFilteredIssues() {
  return allIssues.filter(issue => {
    const typeOk = activeTypeFilter === "ALL" || issue.type === activeTypeFilter;
    const sevOk  = activeSevFilter  === "ALL" || issue.severity === activeSevFilter;
    return typeOk && sevOk;
  });
}
```

### 12.5 Issue List Renderer

```javascript
function renderIssueList() {
  const list    = document.getElementById("issue-list");
  const empty   = document.getElementById("empty-state");
  const filtered = getFilteredIssues();

  list.innerHTML = "";

  if (filtered.length === 0) {
    const em = document.createElement("div");
    em.className = "empty-state";
    em.textContent = allIssues.length === 0
      ? "No issues found. Run a scan."
      : "No issues match the current filters.";
    list.appendChild(em);
    return;
  }

  filtered.forEach(issue => {
    const row = document.createElement("div");
    row.className = "issue-row" + (issue.id === selectedIssueId ? " selected" : "");
    row.dataset.id = issue.id;

    const typeClass = (issue.type || "").toLowerCase();
    const sevClass  = (issue.severity || "LOW").toLowerCase();

    const title = buildIssueTitle(issue);
    const sub   = buildIssueSub(issue);

    row.innerHTML = `
      <div class="issue-left">
        <div class="type-dot ${typeClass}"></div>
        <div class="sev-badge ${sevClass}">${issue.severity || "LOW"}</div>
      </div>
      <div class="issue-body">
        <div class="issue-title">${escHtml(title)}</div>
        <div class="issue-sub">${escHtml(sub)}</div>
      </div>
    `;

    row.addEventListener("click", () => {
      document.querySelectorAll(".issue-row").forEach(r => r.classList.remove("selected"));
      row.classList.add("selected");
      selectedIssueId = issue.id;
      renderDetail(issue);
    });

    list.appendChild(row);
  });
}

function buildIssueTitle(issue) {
  if (issue.type === "XSS") {
    return `${issue.context || ""} XSS — ${issue.sink || ""}`;
  }
  if (issue.type === "SQLi") {
    return `SQLi — ${issue.confidence || ""} confidence`;
  }
  return issue.type || "Unknown";
}

function buildIssueSub(issue) {
  if (issue.type === "XSS") {
    return `${issue.source || ""} → ${issue.variable || ""} → ${issue.sink || ""}`;
  }
  if (issue.type === "SQLi") {
    const url = issue.url || "";
    return url.length > 50 ? "..." + url.slice(-47) : url;
  }
  return issue.detail || "";
}
```

### 12.6 Detail Renderer

```javascript
function renderDetail(issue) {
  const container = document.getElementById("detail-content");

  if (!issue) {
    container.innerHTML = `<div class="empty-state">Select an issue to view details.</div>`;
    return;
  }

  if (issue.type === "XSS") {
    container.innerHTML = buildXSSDetail(issue);
  } else if (issue.type === "SQLi") {
    container.innerHTML = buildSQLiDetail(issue);
  } else {
    container.innerHTML = `<div class="empty-state">${escHtml(issue.detail || "No details.")}</div>`;
  }
}

function buildXSSDetail(issue) {
  const sev = (issue.severity || "").toLowerCase();

  const flowNodes = [
    { icon: "SRC", cls: "source", label: issue.source   || "unknown source",   meta: `line ${issue.sourceLine || "?"}` },
    { icon: "VAR", cls: "var",    label: issue.variable  || "intermediate var", meta: "tainted" },
    { icon: "SNK", cls: "sink",   label: issue.sink      || "unknown sink",     meta: `line ${issue.sinkLine || "?"}` },
  ];

  const flowHTML = flowNodes.map((n, i) => `
    ${i > 0 ? '<div class="flow-connector"></div>' : ""}
    <div class="flow-node">
      <div class="flow-node-icon ${n.cls}">${n.icon}</div>
      <div class="flow-node-label">${escHtml(n.label)}</div>
      <div class="flow-node-meta">${escHtml(n.meta)}</div>
    </div>
  `).join("");

  return `
    <div class="detail-summary">
      <div class="detail-stat">
        <div class="detail-stat-label">Type</div>
        <div class="detail-stat-value" style="color: var(--type-xss)">XSS</div>
      </div>
      <div class="detail-stat">
        <div class="detail-stat-label">Severity</div>
        <div class="detail-stat-value" style="color: var(--sev-${sev})">${issue.severity}</div>
      </div>
      <div class="detail-stat">
        <div class="detail-stat-label">Confidence</div>
        <div class="detail-stat-value">${issue.confidence || "HIGH"}</div>
      </div>
    </div>

    <div class="flow-trace">
      <div class="flow-trace-title">Data Flow Trace</div>
      <div class="flow-chain">${flowHTML}</div>
    </div>

    <div class="context-block">
      <div class="context-block-title">Context Analysis</div>
      <div class="context-row">
        <span class="context-key">Injection context</span>
        <span class="context-value">${escHtml(issue.context || "HTML")}</span>
      </div>
      <div class="context-row">
        <span class="context-key">Sanitization detected</span>
        <span class="context-value" style="color: ${issue.sanitized ? "var(--type-sqli)" : "var(--sev-critical)"}">
          ${issue.sanitized ? "Yes" : "None detected"}
        </span>
      </div>
      <div class="context-row">
        <span class="context-key">Engine</span>
        <span class="context-value">${issue.engine || "AST"}</span>
      </div>
      <div class="context-row">
        <span class="context-key">File</span>
        <span class="context-value">${escHtml(issue.file || "—")}</span>
      </div>
    </div>
  `;
}

function buildSQLiDetail(issue) {
  const evidenceHTML = (issue.evidence || []).map(e => `
    <div class="evidence-item">
      <span class="evidence-bullet">+</span>
      <span>${escHtml(e)}</span>
    </div>
  `).join("") || `<div class="evidence-item"><span>No evidence recorded.</span></div>`;

  const sev = (issue.severity || "").toLowerCase();

  return `
    <div class="detail-summary">
      <div class="detail-stat">
        <div class="detail-stat-label">Type</div>
        <div class="detail-stat-value" style="color: var(--type-sqli)">SQLi</div>
      </div>
      <div class="detail-stat">
        <div class="detail-stat-label">Severity</div>
        <div class="detail-stat-value" style="color: var(--sev-${sev})">${issue.severity}</div>
      </div>
      <div class="detail-stat">
        <div class="detail-stat-label">Score</div>
        <div class="detail-stat-value">${issue.score || 0} pts</div>
      </div>
    </div>

    <div class="context-block">
      <div class="context-block-title">Request Info</div>
      <div class="context-row">
        <span class="context-key">Method</span>
        <span class="context-value">${escHtml(issue.method || "GET")}</span>
      </div>
      <div class="context-row">
        <span class="context-key">Confidence</span>
        <span class="context-value">${escHtml(issue.confidence || "MEDIUM")}</span>
      </div>
      <div class="context-row">
        <span class="context-key">URL</span>
        <span class="context-value" style="font-family: var(--font-mono); font-size: 10px; word-break: break-all;">
          ${escHtml((issue.url || "").substring(0, 100))}
        </span>
      </div>
    </div>

    <div class="evidence-block">
      <div class="context-block-title">Evidence Signals</div>
      ${evidenceHTML}
    </div>
  `;
}
```

### 12.7 Event Stream Renderer

```javascript
function renderEventStream() {
  const tbody = document.getElementById("event-tbody");
  const countEl = document.getElementById("event-count");

  tbody.innerHTML = "";
  countEl.textContent = allEvents.length;

  const recent = allEvents.slice(-100).reverse();

  recent.forEach(ev => {
    const tr = document.createElement("tr");

    const time   = new Date(ev.timestamp).toLocaleTimeString("en-US", { hour12: false });
    const detail = ev.url || ev.detail || "—";
    const flagEl = ev.flag
      ? `<span class="event-flag ${ev.flag.toLowerCase()}">${ev.flag}</span>`
      : `<span style="color: var(--text-muted)">—</span>`;

    tr.innerHTML = `
      <td>${escHtml(time)}</td>
      <td>${escHtml(ev.type || "?")}</td>
      <td>${escHtml(detail.substring(0, 80))}</td>
      <td>${flagEl}</td>
    `;

    tbody.appendChild(tr);
  });
}
```

### 12.8 Live Event Polling

```javascript
function startEventPoll() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => {
    sendToContent("GET_REPORT", (response) => {
      if (!response || !response.success) return;
      allEvents = response.report.events || [];
      renderEventStream();
    });
  }, 3000); // poll every 3 seconds
}
```

### 12.9 Messaging Helper

```javascript
function sendToContent(action, callback) {
  chrome.tabs.query({ active: true, currentWindow: false }, (tabs) => {
    // DevTools inspects the target tab — use chrome.devtools.inspectedWindow.tabId
    const tabId = chrome.devtools.inspectedWindow.tabId;
    chrome.runtime.sendMessage({ action, tabId }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("PixelSpy:", chrome.runtime.lastError.message);
        callback && callback(null);
        return;
      }
      callback && callback(response);
    });
  });
}
```

### 12.10 Utilities

```javascript
function setStatus(text, scanning, issueCount) {
  const el = document.getElementById("status-text");
  const countEl = document.getElementById("issue-count");

  el.textContent = text;
  el.classList.toggle("scanning", !!scanning);

  if (typeof issueCount === "number" && issueCount > 0) {
    countEl.textContent = `${issueCount} issue${issueCount !== 1 ? "s" : ""}`;
    countEl.classList.remove("hidden");
  }
}

function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
```

---

## 13. Inter-Module Communication Map

```
ACTION: RUN_SCAN
  panel.js
    └─ chrome.runtime.sendMessage({ action: "RUN_SCAN", tabId })
         └─ background.js (service worker)
              └─ chrome.tabs.sendMessage(tabId, { action: "RUN_SCAN" })
                   └─ content.js onMessage listener
                        ├─ clears currentReport
                        ├─ calls window.runStaticAnalysis()  ← staticEngine.js
                        └─ sendResponse({ success: true, report: currentReport })
                   └─ background.js relays response back
              └─ panel.js callback receives report
                   ├─ renderIssueList()
                   └─ renderEventStream()

ACTION: GET_REPORT (polling, every 3s)
  panel.js
    └─ (same path as above)
         └─ content.js returns currentReport as-is (no re-scan)
              └─ panel.js updates event stream only
```

---

## 14. Data Schemas

### 14.1 XSS Issue Object
```javascript
{
  id:         "issue_001",          // string, unique
  engine:     "AST",                // "AST" | "RUNTIME"
  type:       "XSS",
  severity:   "HIGH",               // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  context:    "HTML",               // "HTML" | "ATTR" | "JS" | "URL"
  source:     "location.search",    // taint source string
  variable:   "userInput",          // tainted variable name
  sink:       "innerHTML",          // sink identifier
  sourceLine: 12,                   // line number of taint assignment
  sinkLine:   42,                   // line number of sink assignment
  sanitized:  false,
  file:       "inline-script-0",
  confidence: "HIGH",
  timestamp:  1714000000000
}
```

### 14.2 SQLi Issue Object
```javascript
{
  id:         "issue_002",
  engine:     "RUNTIME",
  type:       "SQLi",
  severity:   "MEDIUM",
  url:        "https://example.com/api/user?id=101",
  method:     "GET",
  score:      55,
  confidence: "MEDIUM",             // score >= 70 → HIGH, >= 50 → MEDIUM
  evidence:   [
    "suspicious param name: \"id\"",
    "numeric value in param \"id\""
  ],
  timestamp:  1714000000000
}
```

### 14.3 Runtime Event Object
```javascript
{
  type:      "FETCH",               // "FETCH" | "XHR" | "DOM"
  url:       "https://...",         // for FETCH/XHR
  detail:    "innerHTML changed",   // for DOM
  method:    "GET",
  timestamp: 1714000000000,
  flag:      "SQLi"                 // null | "XSS" | "SQLi"
}
```

### 14.4 Full Report Object (currentReport in content.js)
```javascript
{
  url:      "https://example.com/",
  scanTime: 1714000000000,
  issues:   [ /* XSS and SQLi issue objects */ ],
  events:   [ /* runtime event objects */      ]
}
```

---

## 15. Known Edge Cases the Agent Must Handle

| Scenario | Required Handling |
|---|---|
| `acorn.parse()` throws on malformed JS | Wrap in try/catch, push no issues for that script, continue |
| Content script not injected yet | background.js catches `chrome.runtime.lastError`, panel shows "page not ready" |
| Page has no inline scripts | `extractScripts()` returns `[]`, `runStaticAnalysis()` returns `[]` |
| Same variable assigned from multiple sources | Taint map entry is overwritten with latest source — acceptable for learning scope |
| URL is relative (e.g. `/api/user?id=1`) | `new URL(url)` throws — wrap `scoreRequestForSQLi` in try/catch, return `null` |
| Events array exceeds 200 entries | `trimEvents()` slices to last 200 — prevents memory growth |
| Panel opens before any scan | Both issue list and detail pane show empty state messages |
| Filter yields zero results | Issue list shows "No issues match the current filters" message |
| XSS issue has no flow variable | `buildIssueSub()` handles undefined gracefully via `|| ""` fallbacks |

---

## 16. Build Instructions for developer (agent must tell this to developer after completely building the project)

### Step 1 — Get acorn
```bash
npm install acorn
cp node_modules/acorn/dist/acorn.js extension/acorn.min.js
```

### Step 2 — Generate placeholder icons
Any 16x16, 48x48, 128x128 PNG images. A solid `#4f8ef7` square is sufficient.

### Step 3 — Write all files
Write every file exactly as specced in sections 3–12 of this document. No additions, no omissions.

### Step 4 — Load in Chrome
1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click "Load unpacked"
4. Select the `extension/` folder
5. Open any web page
6. Open Chrome DevTools (F12)
7. Navigate to the "PixelSpy" tab

### Step 5 — Test
Load DVWA or OWASP Juice Shop. Navigate to a page with XSS payloads. Click Scan. Issues should appear in the panel.

---
