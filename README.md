# pci-tokenization-remediation-lab

A working sample of a payment security remediation for an ASP.NET application:
card entry moved to **Authorize.Net Accept.js** and **Braintree Hosted Fields**,
so raw card numbers and CVVs never reach the server, plus the SQL Server cleanup
of card data already stored in an API log and an unused cards table.

Everything here runs offline with only the .NET 8 SDK (no NuGet packages). The
SQL scripts are tested against a real SQL Server 2022 container in CI.

## What is in it

| part | what it does |
|---|---|
| `src/PaymentsDemo/wwwroot/authorize-net.html` + `js/authorize-net-payments.js` | Accept.js page. Card inputs have no `name`, so the browser cannot post them to us. Accept.js returns `opaqueData`, which is the only thing sent to the API. |
| `src/PaymentsDemo/wwwroot/braintree.html` + `js/braintree-payments.js` | Hosted Fields through one shared helper. Card fields are Braintree iframes; only the nonce is posted. |
| `Payments/Gateways.cs` | Server side: charges `opaqueData` via the Authorize.Net JSON API and a nonce via the Braintree GraphQL API. Every gateway request and response is redacted before it is logged. |
| `Security/CardDataGuard.cs` | Middleware that rejects any request still carrying a PAN, a CVV or a card-number field, and logs the path (never the value). It is the regression net for the pages. |
| `Security/CardData.cs` | PAN and CVV detection and masking (Luhn, 13-19 digits, prefix 2-6, keep last 4; CVV values under known keys in JSON, form and XML). |
| `tools/CardFieldScanner` | Inventories every page with card inputs: RAW (posts card data), TOKENIZED, or REVIEW, plus pages nothing links to (candidates for retirement). CSV output, and `--fail-on-raw` for CI. |
| `sql/00_objects.sql` | One reviewable script: T-SQL versions of the same masking rules, a read-only inventory, batched API-log masking (dry run by default), and a guarded drop of the cards table (report-only by default). |
| `sql/01` - `03`, `99` | Runner scripts with safe defaults, in the order a DBA runs them. |
| `docs/remediation-guide.md` | Page-by-page conversion steps (WebForms and MVC), retirement, and the database runbook. |

## One rule set, two implementations, one set of fixtures

`tests/fixtures/redaction_cases.json` holds 20 cases: PANs in JSON, form, XML
and plain-text logs, spaced and dashed formats, Amex, Mastercard 2-series,
several in one line, CVV in each format, and the cases that must **not** be
touched (Luhn-failing order numbers, 20-digit runs, PANs inside longer digit
runs, phone numbers, timestamps, wrong-length CVVs, already-masked values).

The C# tests run them through `CardData.Redact`. The SQL tests load the same
file into SQL Server and require `pci_cleanup.RedactCardData` to produce the
same output character for character. The application and the database
cleanup cannot drift apart.

## Run it

```bash
dotnet build
dotnet run --project tests/PaymentsDemo.Tests            # 38 tests
dotnet run --project tools/CardFieldScanner -- samples/legacy-site
dotnet run --project src/PaymentsDemo                    # http://localhost:5000
```

Sandbox credentials, for live sandbox charges from the pages:

```
AUTHNET_API_LOGIN_ID  AUTHNET_TRANSACTION_KEY  AUTHNET_PUBLIC_CLIENT_KEY
BRAINTREE_PUBLIC_KEY  BRAINTREE_PRIVATE_KEY
```

SQL tests (CI does this on every push):

```bash
docker run -d --name mssql -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='Your!Passw0rd' mcr.microsoft.com/mssql/server:2022-latest
CONTAINER=mssql SA_PASSWORD='Your!Passw0rd' sql/tests/run.sh
```

## Scanner output on the sample legacy site

```
file,status,card_controls,tokenizer,referenced_by
AcceptPay.aspx,TOKENIZED,client:cc-number client:cc-cvv,accept.js,1
Checkout.aspx,RAW,raw:txtCardNumber raw:txtCVV,none,1
OldPayment.aspx,RAW,raw:ccnum raw:cvv2,none,0
PayBalance.aspx,RAW,raw:txtCardNo raw:txtSecurityCode,none,1
Views/Billing/Draft.cshtml,REVIEW,client:card-number-preview,none,0
Views/Billing/Pay.cshtml,RAW,raw:CardNumber raw:Cvv,none,0
```

`OldPayment.aspx` posts card data and nothing links to it, so it is retired,
not converted.

## Database safety rules built into the scripts

- Nothing destructive runs by default: `MaskApiLog @DryRun = 1`, `RetireCardsTable @Execute = 0`.
- `Inventory` only reads.
- Masking runs one transaction per batch, changes only the matched PAN/CVV
  characters, and is safe to stop and re-run (masked rows no longer match).
- The audit table records table, column, row key and time, never a value.
- The cards table is not dropped while any foreign key, view, procedure,
  function or trigger references it.
- Object names are always built from `OBJECT_ID` and `QUOTENAME`, never
  concatenated from input.

## Scope notes

- The sample uses ASP.NET Core. On .NET Framework WebForms/MVC the browser
  side is identical; the guard becomes an `IHttpModule` and the charge calls
  go through the same JSON/GraphQL endpoints or the providers' SDKs.
- Card entry in mobile apps is out of scope here, as it would be in a real
  engagement scoped to the web pages.

This is a public work sample by [Ahmed Darder](https://github.com/Drdr1). It
contains no client code or data; all card numbers are the providers'
published test numbers.
