BraintreePayments.mount({
  form: "#pay", status: "#status",
  number: "#bt-number", expiry: "#bt-expiry", cvv: "#bt-cvv",
  amount: () => Number(document.querySelector("#amount").value),
  orderId: () => document.querySelector("#order").value
}).catch((err) => { document.querySelector("#status").textContent = err.message; });
