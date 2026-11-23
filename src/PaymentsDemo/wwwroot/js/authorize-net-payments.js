// Shared Authorize.Net Accept.js helper. The card inputs have no `name`
// attribute, so the browser can never submit them to our server. Accept.js
// sends the card data straight to Authorize.Net and returns opaqueData (a
// payment nonce), which is the only thing we post to our API.
(function (global) {
  "use strict";

  async function getConfig() {
    const res = await fetch("/api/payments/config", { credentials: "same-origin" });
    return (await res.json()).authorizeNet;
  }

  function mount(options) {
    const form = document.querySelector(options.form);
    const status = document.querySelector(options.status);
    const field = (sel) => form.querySelector(sel);
    let config = null;
    getConfig().then((c) => { config = c; });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!config || !config.configured) {
        status.textContent = "Payments are not configured.";
        return;
      }
      const secureData = {
        authData: { clientKey: config.clientKey, apiLoginID: config.apiLoginId },
        cardData: {
          cardNumber: field(options.number).value.replace(/\D/g, ""),
          month: field(options.month).value,
          year: field(options.year).value,
          cardCode: field(options.cvv).value
        }
      };
      status.textContent = "Processing...";
      global.Accept.dispatchData(secureData, async function (response) {
        // Wipe the card inputs as soon as Accept.js has them.
        [options.number, options.month, options.year, options.cvv].forEach((s) => { field(s).value = ""; });
        if (response.messages.resultCode === "Error") {
          status.textContent = "Payment failed: " + response.messages.message.map((m) => m.text).join("; ");
          return;
        }
        const res = await fetch(options.chargeUrl || "/api/payments/authorize-net", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ opaqueData: response.opaqueData, amount: options.amount(), invoiceNumber: options.invoiceNumber() })
        });
        const body = await res.json();
        status.textContent = res.ok ? "Payment approved: " + body.transactionId : "Payment failed: " + (body.message || "error");
      });
    });
  }

  global.AuthorizeNetPayments = { mount: mount };
})(window);
