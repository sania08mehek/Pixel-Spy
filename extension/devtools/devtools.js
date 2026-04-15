// devtools.js — Registers the PixelSpy panel inside Chrome DevTools
chrome.devtools.panels.create(
    "PixelSpy",
    "",
    "../panel/panel.html",
    function (panel) {
        // Panel created — no additional setup needed
    }
);
