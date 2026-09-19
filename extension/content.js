(function () {

    // Don't create the notification twice
    if (document.getElementById("trustveil-notification")) {
        return;
    }

    const notification = document.createElement("div");

    notification.id = "trustveil-notification";

    notification.innerHTML = `
        <div class="trustveil-top">
            <div class="trustveil-brand">
                <div class="trustveil-icon">T</div>
                <span>TrustVeil</span>
            </div>

            <button id="trustveil-close">×</button>
        </div>

        <div class="trustveil-message">
            We peeked behind this site.
        </div>

        <div class="trustveil-action">
            Tap to see what we found →
        </div>
    `;

    document.body.appendChild(notification);


    // Close button
    document
        .getElementById("trustveil-close")
        .addEventListener("click", function (event) {

            event.stopPropagation();

            notification.remove();
        });


    // Clicking the notification
   notification.addEventListener("click", function () {

    chrome.runtime.sendMessage({
        action: "openTrustVeil",
        url: window.location.href
    });

});

})();