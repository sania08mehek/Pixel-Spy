// staticEngine.js — PixelSpy AST-based static taint analysis engine
// Loaded as content script. Depends on window.acorn (loaded before this file).

// ── Constants ─────────────────────────────────────────────────────────────────

const SOURCES = [
    "location.search",
    "location.hash",
    "document.cookie",
    "localStorage.getItem",
    "sessionStorage.getItem",
    "document.referrer",
    "window.name",
    ".value" // Catch generic input value sources
];

const SINKS = {
    "innerHTML":            { severity: "HIGH",     context: "HTML",  owaspId: "A03" },
    "outerHTML":            { severity: "HIGH",     context: "HTML",  owaspId: "A03" },
    "insertAdjacentHTML":   { severity: "HIGH",     context: "HTML",  owaspId: "A03" },
    "eval":                 { severity: "CRITICAL", context: "JS",    owaspId: "A03" },
    "setTimeout":           { severity: "HIGH",     context: "JS",    owaspId: "A03" },
    "setInterval":          { severity: "HIGH",     context: "JS",    owaspId: "A03" },
    "document.write":       { severity: "HIGH",     context: "HTML",  owaspId: "A03" },
    "document.writeln":     { severity: "HIGH",     context: "HTML",  owaspId: "A03" },
    "Function":             { severity: "CRITICAL", context: "JS",    owaspId: "A03" },
    "src":                  { severity: "MEDIUM",   context: "ATTR",  owaspId: "A03" },
    "href":                 { severity: "MEDIUM",   context: "URL",   owaspId: "A03" }
};

const SANITIZERS = [
    "DOMPurify.sanitize",
    "encodeURIComponent",
    "encodeURI",
    "escape",
    "htmlspecialchars",
    "sanitize",
    "textContent"
];

const SQLI_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
    "WHERE", "FROM", "TABLE", "--", "OR 1=1", "' OR '", "xp_", "EXEC",
    "GROUP BY", "ORDER BY", "HAVING", "LIMIT", "OFFSET", "INFORMATION_SCHEMA",
    "SLEEP(", "BENCHMARK(", "CHAR(", "CONCAT("
];

const SQLI_PARAM_NAMES = [
    "id", "user", "username", "query", "search",
    "filter", "sort", "order", "category", "type",
    "page", "limit", "offset", "product", "item",
    "key", "auth", "token", "password"
];

// Dangerous React patterns
const REACT_DANGEROUS = ["dangerouslySetInnerHTML"];

// Crypto weakness patterns (weak algorithms)
const WEAK_CRYPTO = ["MD5", "SHA1", "SHA-1", "RC4", "DES", "createCipheriv", "createHash"];

// Fix recommendations per sink/context
const FIX_RECOMMENDATIONS = {
    "innerHTML":          "Use textContent instead of innerHTML, or sanitize with DOMPurify.sanitize() before assignment.",
    "outerHTML":          "Avoid outerHTML with user data. Prefer DOM manipulation APIs (createElement, textContent).",
    "insertAdjacentHTML": "Use insertAdjacentText() or sanitize input with DOMPurify.sanitize() first.",
    "eval":               "Never pass user-controlled data to eval(). Refactor to avoid code-as-string execution.",
    "setTimeout":         "Pass a function reference to setTimeout, not a string. String-form setTimeout() evaluates code.",
    "setInterval":        "Pass a function reference to setInterval, not a string. String-form evaluates code.",
    "document.write":     "Remove document.write(). Use DOM APIs instead. It's unsafe and blocks the parser.",
    "Function":           "Avoid the Function() constructor with dynamic strings. It behaves like eval().",
    "src":                "Validate URLs against an allowlist before setting src attributes.",
    "href":               "Check that URLs start with https:// before assigning to href. Block javascript: URLs.",
    "DEFAULT":            "Sanitize all user-controlled data before using it in sensitive DOM contexts."
};

// ── Issue counter ─────────────────────────────────────────────────────────────
let _issueCounter = 0;

// ── Main Export ───────────────────────────────────────────────────────────────

window.runStaticAnalysis = function () {
    const issues = [];
    const scripts = extractScripts();

    scripts.forEach((src, idx) => {
        try {
            const ast = acorn.parse(src, {
                ecmaVersion: 2022,
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

// ── Script Extraction ─────────────────────────────────────────────────────────

function extractScripts() {
    const scripts = [];
    document.querySelectorAll("script:not([src])").forEach(el => {
        if (el.textContent.trim().length > 0) {
            scripts.push(el.textContent);
        }
    });
    return scripts;
}

// ── AST Analyzer ──────────────────────────────────────────────────────────────

function analyzeAST(ast, src, fileLabel) {
    const issues = [];
    // taintedVars: Map<string, { source: string, line: number }>
    const taintedVars = new Map();

    function walk(node, parent) {
        if (!node || typeof node !== "object") return;

        // --- TAINT ASSIGNMENT DETECTION ---
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

                // Propagate taint through intermediate variables
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

        // --- SINK DETECTION: element.innerHTML = taintedVar ---
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
                                type: "XSS",
                                severity: sinkInfo.severity,
                                context: sinkInfo.context,
                                owaspId: sinkInfo.owaspId,
                                source: taintInfo.source,
                                variable: v,
                                sink: sinkName,
                                sourceLine: taintInfo.line,
                                sinkLine: node.loc ? node.loc.start.line : 0,
                                sanitized: false,
                                file: fileLabel,
                                confidence: "HIGH",
                                recommendation: FIX_RECOMMENDATIONS[sinkName] || FIX_RECOMMENDATIONS["DEFAULT"]
                            }));
                        }
                    }
                });
            }

            // --- React dangerouslySetInnerHTML pattern ---
            if (node.left && node.left.type === "MemberExpression") {
                const prop = node.left.property && (node.left.property.name || "");
                if (REACT_DANGEROUS.includes(prop)) {
                    const usedVars = collectIdentifiers(node.right);
                    usedVars.forEach(v => {
                        if (taintedVars.has(v) && !hasSanitizer(node.right)) {
                            issues.push(buildIssue({
                                type: "XSS",
                                severity: "HIGH",
                                context: "React",
                                owaspId: "A03",
                                source: taintedVars.get(v).source,
                                variable: v,
                                sink: "dangerouslySetInnerHTML",
                                sinkLine: node.loc ? node.loc.start.line : 0,
                                sanitized: false,
                                file: fileLabel,
                                confidence: "HIGH",
                                recommendation: "Sanitize with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML. Better yet, avoid it entirely."
                            }));
                        }
                    });
                }
            }
        }

        // --- SINK DETECTION: eval(taintedVar), setTimeout(taintedVar, ...) ---
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
                                type: "XSS",
                                severity: sinkInfo.severity,
                                context: sinkInfo.context,
                                owaspId: sinkInfo.owaspId,
                                source: taintInfo.source,
                                variable: v,
                                sink: calleeName + "()",
                                sourceLine: taintInfo.line,
                                sinkLine: node.loc ? node.loc.start.line : 0,
                                sanitized: false,
                                file: fileLabel,
                                confidence: "HIGH",
                                recommendation: FIX_RECOMMENDATIONS[calleeName] || FIX_RECOMMENDATIONS["DEFAULT"]
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

// ── Helper Functions ──────────────────────────────────────────────────────────

function matchesSource(node) {
    if (!node) return null;

    if (node.type === "MemberExpression") {
        const str = memberExprToString(node);
        for (const src of SOURCES) {
            if (str === src || str.endsWith(src) || str.includes("." + src)) return src;
        }
    }

    if (node.type === "CallExpression") {
        const str = memberExprToString(node.callee);
        for (const src of SOURCES) {
            if (str === src || str.startsWith(src)) return src;
        }
    }

    return null;
}

function memberExprToString(node) {
    if (!node) return "";
    if (node.type === "Identifier") return node.name;
    if (node.type === "MemberExpression") {
        return memberExprToString(node.object) + "." + memberExprToString(node.property);
    }
    return "";
}

function extractName(node) {
    if (!node) return null;
    if (node.type === "Identifier") return node.name;
    return null;
}

function extractSinkName(node) {
    if (!node) return null;
    if (node.type === "MemberExpression" && node.property) {
        const prop = node.property.name || node.property.value;
        if (prop && SINKS[prop]) return prop;
    }
    return null;
}

function extractCalleeName(node) {
    if (!node) return null;
    if (node.type === "Identifier") return node.name;
    if (node.type === "MemberExpression") {
        return node.property ? (node.property.name || null) : null;
    }
    return null;
}

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

function buildIssue(fields) {
    return {
        id: `issue_${String(++_issueCounter).padStart(3, "0")}`,
        engine: "AST",
        timestamp: Date.now(),
        ...fields
    };
}

// ── SQLi Heuristic Scorer ─────────────────────────────────────────────────────
// Used by content.js hooks. Exported from staticEngine.js

window.scoreRequestForSQLi = function (url, method) {
    if (!url || typeof url !== "string") return null;

    let score = 0;
    const evidence = [];
    let params = [];

    // ── Robust URL param extraction ────────────────────────────────────────────
    // Bug: window.location.origin returns the string "null" for file:// pages.
    // We guard against this and fall back to a dummy base so relative paths work.
    try {
        const origin = window.location.origin;
        // "null" (string) is returned by browsers for file:// pages
        const safeBase = (!origin || origin === "null") ? "http://localhost" : origin;
        const parsed = new URL(url, safeBase);
        params = [...parsed.searchParams.entries()];
    } catch (e) {
        // Last-resort: manually extract the query string
        try {
            const qs = url.includes("?") ? url.split("?")[1].split("#")[0] : "";
            if (qs) {
                qs.split("&").forEach(pair => {
                    const [k, v] = pair.split("=");
                    if (k) params.push([decodeURIComponent(k), decodeURIComponent(v || "")]);
                });
            }
        } catch (_) { /* ignore */ }
    }

    // No params = skip
    if (params.length === 0) return null;

    params.forEach(([key, value]) => {
        const upperVal = value.toUpperCase();

        // Layer 1: SQL keyword presence in value
        SQLI_KEYWORDS.forEach(kw => {
            if (upperVal.includes(kw.toUpperCase())) {
                score += 35;
                evidence.push(`SQL keyword "${kw}" found in param "${key}"`);
            }
        });

        // Layer 2a: Suspicious parameter name
        if (SQLI_PARAM_NAMES.includes(key.toLowerCase())) {
            score += 25;
            evidence.push(`Suspicious param name: "${key}"`);
        }

        // Layer 2b: Numeric value (common id-based injection targets)
        if (/^\d+$/.test(value)) {
            score += 15;
            evidence.push(`Numeric value in param "${key}" = ${value}`);
        }

        // Layer 3: Quote characters or comment sequences
        if (/['";]/.test(value)) {
            score += 30;
            evidence.push(`Quotes or semi-colon in param "${key}"`);
        }
        if (value.includes("--") || value.includes("/*") || value.includes("#")) {
            score += 30;
            evidence.push(`SQL comment sequence in param "${key}"`);
        }

        // Layer 4: URL-encoded injection payloads
        if (/%27|%22|%3B|%2D%2D|%2F%2A/i.test(value)) {
            score += 30;
            evidence.push(`URL-encoded injection chars in param "${key}"`);
        }

        // Layer 5: Tautologies
        if (/1\s*=\s*1|0\s*=\s*0/i.test(value)) {
            score += 40;
            evidence.push(`Tautology (e.g. 1=1) detected in param "${key}"`);
        }
    });

    if (score === 0) return null;

    const confidence = score >= 70 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW";
    const severity   = score >= 70 ? "HIGH" : "MEDIUM";

    return {
        id: `issue_${String(++_issueCounter).padStart(3, "0")}`,
        engine: "RUNTIME",
        type: "SQLi",
        url,
        method: method || "GET",
        score,
        confidence,
        severity,
        evidence,
        owaspId: "A03",
        recommendation: "Use parameterized queries / prepared statements on the backend. Never concatenate user input into SQL strings.",
        timestamp: Date.now()
    };
};
