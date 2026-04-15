// background.js — PixelSpy service worker
// Acts as a stateless message relay between the DevTools panel and content script.

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Panel asking for report or triggering scan
  if (msg.action === "GET_REPORT" || msg.action === "RUN_SCAN") {
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

    return true; // keep message channel open for async sendResponse
  }
});
