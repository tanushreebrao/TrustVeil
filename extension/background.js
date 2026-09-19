chrome.runtime.onMessage.addListener((message, sender) => {
    if (message.action === "openTrustVeil" && sender.tab) {
        const targetTabId = sender.tab.id;

        chrome.windows.create({
            url: chrome.runtime.getURL(
                `popup.html?autoAnalyze=true&tabId=${targetTabId}`
            ),
            type: "popup",
            width: 420,
            height: 650
        });
    }
});