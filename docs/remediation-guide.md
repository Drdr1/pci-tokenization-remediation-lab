# Remediation guide: one payment page at a time

The order that keeps checkout working the whole time.

## 1. Inventory

Run the scanner on the site root and keep the CSV with the ticket:

```
dotnet run --project tools/CardFieldScanner -- path/to/site > card-pages.csv
```

Each page lands in one bucket:

| status | action |
|---|---|
| RAW, referenced | convert (step 2) |
| RAW, `referenced_by = 0` | confirm with analytics/IIS logs that nothing hits it, then retire (step 4) |
| REVIEW | read it: a preview or label is fine, an unfinished form gets converted or removed |
| TOKENIZED | check it posts only `opaqueData` / a nonce (step 3) |

`referenced_by` counts files that mention the page name. MVC views are reached
through routes, so for `.cshtml` files check the controller instead.

## 2. Convert a page

**Authorize.Net (WebForms example).** Replace the server-side card boxes:

```aspx
<asp:TextBox ID="txtCardNumber" runat="server" />   <!-- before: posts the PAN -->
```

with plain inputs that have **no `name` and no `runat`**, plus two hidden
fields that carry the token:

```aspx
<input id="cc-number" autocomplete="cc-number">
<input id="cc-cvv" autocomplete="cc-csc">
<asp:HiddenField ID="dataDescriptor" runat="server" />
<asp:HiddenField ID="dataValue" runat="server" />
```

Accept.js fills the hidden fields in its callback, then the form posts. The
code-behind builds the charge with `opaqueData` instead of `creditCardType`
and never reads a card field again. `wwwroot/js/authorize-net-payments.js`
shows the browser half.

**Braintree.** Replace the card inputs with three empty `<div>` containers and
call the shared `braintree-payments.js` helper. It tokenizes inside
Braintree's iframes and posts only the nonce. Server-side `Transaction.Sale`
switches from `CreditCard = {...}` to `PaymentMethodNonce = nonce`.

## 3. Prove the page is clean

- The scanner reports the page as TOKENIZED.
- In the browser dev tools, the form post contains only the token fields.
- With the `CardDataGuard` middleware (or its `HttpModule` equivalent on
  .NET Framework) in place, any request still carrying a PAN or CVV gets a
  400 and a log line naming the page. Run it in log-only mode first, then
  switch it to blocking.

## 4. Retire unused pages

Remove the page, its code-behind and its route, and add a 301 to the
current payment page so old bookmarks still work.

## 5. Database

1. `sql/00_objects.sql`: creates the helpers in schema `pci_cleanup`. No data changes.
2. `sql/01_inventory_readonly.sql`: read-only counts. Record the numbers.
3. `sql/02_mask_apilog.sql`: dry run first (`@DryRun = 1`), then after a backup
   `@DryRun = 0`. One transaction per batch, re-runnable, audit rows hold keys only.
4. `sql/03_retire_pt_patientcards.sql`: report first. Remove the table from
   the data model (EF model / EDMX / DataSet) and deploy, then `@Execute = 1`.
   It refuses while any FK, view, procedure or trigger still references it.
5. `sql/99_drop_objects.sql`: removes the helpers and keeps the audit table.

**Backups.** Masking and dropping do not remove card data from existing
backups or the transaction log. Expire or securely destroy old backups on
your normal schedule and note the date in the PCI evidence.
