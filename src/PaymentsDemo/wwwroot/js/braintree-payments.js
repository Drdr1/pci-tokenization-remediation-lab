// Shared Braintree Hosted Fields helper. Every Braintree payment page calls
// BraintreePayments.mount(...) instead of rendering its own card inputs.
// Card number, expiry and CVV live inside Braintree-hosted iframes; this page
// (and our server) only ever sees the one-time nonce.
(function (global) {
  "use strict";

  async function getClientToken() {
    const res = await fetch("/api/payments/braintree/client-token", { credentials: "same-origin" });
    if (!res.ok) throw new Error("Could not start the payment form.");
    return (await res.json()).clientToken;
  }

  async function mount(options) {
    const form = document.querySelector(options.form);
    const submit = form.querySelector("[type=submit]");
    const status = document.querySelector(options.status);
    submit.disabled = true;

    const client = await global.braintree.client.create({ authorization: await getClientToken() });
    const hostedFields = await global.braintree.hostedFields.create({
      client: client,
      fields: {
        number: { container: options.number, placeholder: "Card number" },
        expirationDate: { container: options.expiry, placeholder: "MM/YY" },
        cvv: { container: options.cvv, placeholder: "CVV" }
      }
    });
    submit.disabled = false;

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      submit.disabled = true;
      status.textContent = "Processing...";
      try {
        const payload = await hostedFields.tokenize();
        const res = await fetch(options.chargeUrl || "/api/payments/braintree", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: payload.nonce, amount: options.amount(), orderId: options.orderId() })
        });
        const body = await res.json();
        status.textContent = res.ok ? "Payment approved: " + body.transactionId : "Payment failed: " + (body.message || "error");
        if (res.ok) hostedFields.clear("number"), hostedFields.clear("cvv"), hostedFields.clear("expirationDate");
      } catch (err) {
        status.textContent = "Payment failed: " + err.message;
      } finally {
        submit.disabled = false;
      }
    });
    return hostedFields;
  }

  global.BraintreePayments = { mount: mount };
})(window);
