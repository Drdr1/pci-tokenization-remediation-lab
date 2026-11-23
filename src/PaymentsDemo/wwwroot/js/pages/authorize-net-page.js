AuthorizeNetPayments.mount({
  form: "#pay", status: "#status",
  number: "#cc-number", month: "#cc-month", year: "#cc-year", cvv: "#cc-cvv",
  amount: () => Number(document.querySelector("#amount").value),
  invoiceNumber: () => document.querySelector("#invoice").value
});
