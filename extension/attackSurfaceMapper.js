// attackSurfaceMapper.js — PixelSpy Attack Surface Analysis Module
// Scans the current page for all input vectors, output sinks, and third-party dependencies.
// Exports: window.mapAttackSurface()

window.mapAttackSurface = function () {
    const surface = {
        forms: [],
        inputs: [],
        externalScripts: [],
        iframes: [],
        externalLinks: [],
        cookies: _parseCookies(),
        localStorage: _scanLocalStorage(),
        urlParams: _getUrlParams(),
        metadata: {
            url: location.href,
            title: document.title,
            timestamp: Date.now(),
            totalInputVectors: 0,
            riskPoints: 0,
            findings: []   // human-readable risk findings
        }
    };

    // ── Forms ──────────────────────────────────────────────────────────────────
    document.querySelectorAll("form").forEach((form, idx) => {
        const inputs = Array.from(
            form.querySelectorAll("input, textarea, select")
        ).map(el => ({
            tag: el.tagName.toLowerCase(),
            type: el.type || el.tagName.toLowerCase(),
            name: el.name || el.id || `field-${idx}`,
            id: el.id || null,
            autocomplete: el.autocomplete || null,
            required: el.required || false
        }));

        const action = form.action || location.href;
        const method = (form.method || "GET").toUpperCase();
        const hasPassword = inputs.some(i => i.type === "password");
        const isHTTPS = action.startsWith("https:");
        const hasCsrfToken = inputs.some(i =>
            /csrf|token|_token|authenticity/i.test(i.name)
        );

        surface.forms.push({
            id: form.id || `form-${idx}`,
            action,
            method,
            inputCount: inputs.length,
            inputs,
            hasPasswordField: hasPassword,
            isHTTPS,
            hasCsrfToken,
            enctype: form.enctype || "application/x-www-form-urlencoded"
        });

        surface.metadata.totalInputVectors += inputs.length;

        // Risk findings
        if (hasPassword && !isHTTPS) {
            surface.metadata.riskPoints += 40;
            surface.metadata.findings.push({
                severity: "CRITICAL",
                text: `Form #${form.id || idx} submits password over HTTP`
            });
        }
        if (method === "GET" && hasPassword) {
            surface.metadata.riskPoints += 20;
            surface.metadata.findings.push({
                severity: "HIGH",
                text: `Form #${form.id || idx} sends password as GET param (visible in URL)`
            });
        }
        if (method === "POST" && !hasCsrfToken) {
            surface.metadata.riskPoints += 15;
            surface.metadata.findings.push({
                severity: "MEDIUM",
                text: `Form #${form.id || idx} (POST) has no CSRF token field`
            });
        }
    });

    // ── Standalone inputs (outside forms) ─────────────────────────────────────
    document.querySelectorAll("input:not(form input), textarea:not(form textarea)").forEach((el, idx) => {
        surface.inputs.push({
            tag: el.tagName.toLowerCase(),
            type: el.type || "text",
            name: el.name || el.id || `input-${idx}`,
            id: el.id || null
        });
        surface.metadata.totalInputVectors++;
    });

    // ── External scripts ───────────────────────────────────────────────────────
    document.querySelectorAll("script[src]").forEach(script => {
        const src = script.src;
        if (!src) return;
        const isExternal = !src.startsWith(location.origin) && !src.startsWith("/") && src.startsWith("http");

        surface.externalScripts.push({
            src: src.length > 120 ? src.substring(0, 117) + "..." : src,
            isExternal,
            hasSRI: !!script.integrity,
            crossOrigin: script.crossOrigin || null,
            isAsync: script.async,
            isDefer: script.defer
        });

        if (isExternal && !script.integrity) {
            surface.metadata.riskPoints += 15;
            surface.metadata.findings.push({
                severity: "MEDIUM",
                text: `External script without SRI: ${_domain(src)}`
            });
        }
    });

    // ── iframes ────────────────────────────────────────────────────────────────
    document.querySelectorAll("iframe").forEach((el, idx) => {
        const src = el.src || null;
        const isExternal = src && !src.startsWith(location.origin);
        const hasSandbox = el.sandbox && el.sandbox.length > 0;

        surface.iframes.push({
            src: src ? src.substring(0, 100) : null,
            isExternal,
            hasSandbox,
            sandbox: el.sandbox.value || null,
            allow: el.allow || null
        });

        if (isExternal && !hasSandbox) {
            surface.metadata.riskPoints += 25;
            surface.metadata.findings.push({
                severity: "HIGH",
                text: `External iframe without sandbox: ${_domain(src)}`
            });
        }
    });

    // ── External links ─────────────────────────────────────────────────────────
    let linkCount = 0;
    let noOpenerCount = 0;
    document.querySelectorAll("a[href]").forEach(el => {
        const href = el.href || "";
        const isExternal = href.startsWith("http") && !href.startsWith(location.origin);
        if (!isExternal) return;
        const hasNoOpener = (el.rel || "").includes("noopener");
        if (!hasNoOpener) noOpenerCount++;
        linkCount++;
        if (surface.externalLinks.length < 30) {
            surface.externalLinks.push({
                href: href.substring(0, 100),
                text: el.textContent.trim().substring(0, 40),
                hasRelNoopener: hasNoOpener,
                hasRelNoreferrer: (el.rel || "").includes("noreferrer")
            });
        }
    });

    if (noOpenerCount > 0) {
        surface.metadata.riskPoints += Math.min(noOpenerCount * 2, 15);
        surface.metadata.findings.push({
            severity: "LOW",
            text: `${noOpenerCount} external link(s) missing rel="noopener noreferrer"`
        });
    }

    // ── Cookie risk ────────────────────────────────────────────────────────────
    if (surface.cookies.length > 0) {
        surface.metadata.findings.push({
            severity: "INFO",
            text: `${surface.cookies.length} cookie(s) visible to JS (httpOnly not set on these)`
        });
        surface.metadata.riskPoints += surface.cookies.length * 3;
    }

    // ── localStorage sensitive keys ────────────────────────────────────────────
    const sensitiveLsKeys = surface.localStorage.filter(i => i.looksLikeSensitive);
    if (sensitiveLsKeys.length > 0) {
        surface.metadata.riskPoints += sensitiveLsKeys.length * 10;
        surface.metadata.findings.push({
            severity: "MEDIUM",
            text: `${sensitiveLsKeys.length} sensitive-looking key(s) in localStorage: ${sensitiveLsKeys.map(i => i.key).join(", ")}`
        });
    }

    // ── URL parameters ─────────────────────────────────────────────────────────
    if (surface.urlParams.length > 0) {
        surface.metadata.riskPoints += surface.urlParams.length * 5;
        surface.metadata.findings.push({
            severity: "INFO",
            text: `${surface.urlParams.length} URL parameter(s) present — potential injection vectors`
        });
    }

    surface.metadata.totalInputVectors += surface.inputs.length;

    return surface;
};

// ── Private helpers ───────────────────────────────────────────────────────────

function _parseCookies() {
    if (!document.cookie) return [];
    return document.cookie.split(";").map(c => {
        const parts = c.trim().split("=");
        return {
            name: (parts[0] || "").trim(),
            // Note: Secure/HttpOnly/SameSite flags can't be read from JS
            // If a cookie is readable here, it means HttpOnly is NOT set
            jsReadable: true
        };
    }).filter(c => c.name.length > 0);
}

function _scanLocalStorage() {
    const items = [];
    try {
        for (const key of Object.keys(localStorage)) {
            const val = localStorage.getItem(key) || "";
            items.push({
                key,
                valueLength: val.length,
                looksLikeSensitive: /token|auth|password|secret|key|session|jwt|bearer/i.test(key)
            });
        }
    } catch (e) { /* cross-origin or restricted */ }
    return items;
}

function _getUrlParams() {
    const params = [];
    try {
        const parsed = new URLSearchParams(location.search);
        for (const [key, value] of parsed.entries()) {
            params.push({
                key,
                value: value.substring(0, 60),
                looksNumeric: /^\d+$/.test(value)
            });
        }
    } catch (e) { /* ignore */ }
    return params;
}

function _domain(url) {
    try { return new URL(url).hostname; } catch (e) { return url.substring(0, 40); }
}
