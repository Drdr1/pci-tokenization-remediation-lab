// Self-contained test runner (no NuGet packages): `dotnet run --project tests/PaymentsDemo.Tests`.
// Each test is a named async lambda; the process exits non-zero if any test fails.

using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using PaymentsDemo;
using PaymentsDemo.Payments;
using PaymentsDemo.Security;

var root = FindRepoRoot();
var tests = new List<(string Name, Func<Task> Body)>();
void Test(string name, Func<Task> body) => tests.Add((name, body));
void Sync(string name, Action body) => tests.Add((name, () => { body(); return Task.CompletedTask; }));

// ---------------------------------------------------------------- redaction
var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "tests/fixtures/redaction_cases.json")))!.AsArray();
foreach (var c in cases)
{
    var name = c!["name"]!.GetValue<string>();
    var input = c["input"]!.GetValue<string>();
    var expected = c["expected"]!.GetValue<string>();
    Sync($"redact: {name}", () =>
    {
        Assert.Equal(expected, CardData.Redact(input));
        Assert.Equal(expected != input, CardData.ContainsCardData(input));
        Assert.Equal(expected, CardData.Redact(expected)); // idempotent
    });
}

Sync("luhn: known values", () =>
{
    Assert.True(CardData.PassesLuhn("4111111111111111"));
    Assert.True(CardData.PassesLuhn("378282246310005"));
    Assert.False(CardData.PassesLuhn("4111111111111112"));
});

// ---------------------------------------------------------------- HTTP: guard, endpoints, gateways
await using var host = await TestHost.StartAsync(Path.Combine(root, "src/PaymentsDemo"));
var http = host.Client;

Test("guard: raw card JSON to the charge endpoint is rejected before the gateway", async () =>
{
    host.Reset();
    var resp = await http.PostAsJsonAsync("/api/payments/authorize-net",
        new { cardNumber = "4111111111111111", cardCode = "123", amount = 10m, invoiceNumber = "INV1" });
    Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    Assert.Contains("card_data_not_accepted", await resp.Content.ReadAsStringAsync());
    Assert.Equal(0, host.AuthNet.Requests.Count);
});

Test("guard: legacy form post with a card field name is rejected", async () =>
{
    var resp = await http.PostAsync("/legacy/checkout", new FormUrlEncodedContent(
        new Dictionary<string, string> { ["txtCardNumber"] = "4111 1111 1111 1111", ["amount"] = "10" }));
    Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
});

Test("guard: card field name with a non-PAN value is still rejected", async () =>
{
    var resp = await http.PostAsync("/legacy/checkout", new FormUrlEncodedContent(
        new Dictionary<string, string> { ["cardNumber"] = "12", ["amount"] = "10" }));
    Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
});

Test("guard: PAN in the query string is rejected", async () =>
{
    var resp = await http.GetAsync("/api/payments/config?ref=4111-1111-1111-1111");
    Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
});

Test("guard: CVV alone is rejected", async () =>
{
    var resp = await http.PostAsync("/api/payments/braintree",
        new StringContent("{\"nonce\":\"abc\",\"cvv\":\"123\",\"amount\":5,\"orderId\":\"O1\"}", Encoding.UTF8,
            "application/json"));
    Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
});

Test("guard: the error response never echoes the card number", async () =>
{
    var resp = await http.PostAsJsonAsync("/api/payments/braintree", new { nonce = "4111111111111111", amount = 1m, orderId = "O" });
    Assert.DoesNotContain("4111111111111111", await resp.Content.ReadAsStringAsync());
});

Test("authorize.net: token-only charge is sent as opaqueData and approved", async () =>
{
    host.Reset();
    host.AuthNet.Reply("﻿{\"transactionResponse\":{\"responseCode\":\"1\",\"transId\":\"60123456789\"}," +
                       "\"messages\":{\"resultCode\":\"Ok\",\"message\":[{\"code\":\"I00001\",\"text\":\"Successful.\"}]}}");
    var resp = await http.PostAsJsonAsync("/api/payments/authorize-net", new
    {
        opaqueData = new { dataDescriptor = AuthorizeNetGateway.AcceptDescriptor, dataValue = "eyJjb2RlIjoiNTBfMl8w" },
        amount = 25.00m,
        invoiceNumber = "INV-1001",
    });
    Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    var body = await resp.Content.ReadFromJsonAsync<JsonObject>();
    Assert.Equal("60123456789", body!["transactionId"]!.GetValue<string>());

    var sent = JsonNode.Parse(host.AuthNet.Requests.Single().Body)!["createTransactionRequest"]!;
    var tx = sent["transactionRequest"]!;
    Assert.Equal("authCaptureTransaction", tx["transactionType"]!.GetValue<string>());
    Assert.Equal("25.00", tx["amount"]!.GetValue<string>());
    Assert.Equal(AuthorizeNetGateway.AcceptDescriptor, tx["payment"]!["opaqueData"]!["dataDescriptor"]!.GetValue<string>());
    Assert.True(tx["payment"]!["creditCard"] is null, "no creditCard element may be sent");
    Assert.Equal("INV-1001", tx["order"]!["invoiceNumber"]!.GetValue<string>());
});

Sync("authorize.net: transaction key never reaches the API log", () =>
{
    Assert.True(host.ApiLog.Entries.Count > 0, "expected log entries");
    Assert.True(host.ApiLog.Entries.All(e => !e.Contains(TestHost.TransactionKey)), "transaction key leaked to the log");
});

Test("authorize.net: decline is returned as 422 with the gateway reason", async () =>
{
    host.AuthNet.Reply("{\"transactionResponse\":{\"responseCode\":\"2\",\"errors\":[{\"errorCode\":\"2\"," +
                       "\"errorText\":\"This transaction has been declined.\"}]},\"messages\":{\"resultCode\":\"Error\"," +
                       "\"message\":[{\"code\":\"E00027\",\"text\":\"The transaction was unsuccessful.\"}]}}");
    var resp = await http.PostAsJsonAsync("/api/payments/authorize-net", new
    {
        opaqueData = new { dataDescriptor = AuthorizeNetGateway.AcceptDescriptor, dataValue = "x" },
        amount = 5m, invoiceNumber = "INV2",
    });
    Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    Assert.Contains("declined", await resp.Content.ReadAsStringAsync());
});

Test("authorize.net: wrong descriptor, bad amount and long invoice are rejected", async () =>
{
    host.Reset();
    var bad = new object[]
    {
        new { opaqueData = new { dataDescriptor = "OTHER", dataValue = "x" }, amount = 5m, invoiceNumber = "I" },
        new { opaqueData = new { dataDescriptor = AuthorizeNetGateway.AcceptDescriptor, dataValue = "x" }, amount = 0.001m, invoiceNumber = "I" },
        new { opaqueData = new { dataDescriptor = AuthorizeNetGateway.AcceptDescriptor, dataValue = "x" }, amount = 5m, invoiceNumber = new string('A', 21) },
        new { opaqueData = new { dataDescriptor = AuthorizeNetGateway.AcceptDescriptor, dataValue = "" }, amount = 5m, invoiceNumber = "I" },
    };
    foreach (var b in bad)
    {
        var resp = await http.PostAsJsonAsync("/api/payments/authorize-net", b);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
    Assert.Equal(0, host.AuthNet.Requests.Count);
});

Test("braintree: nonce charge uses GraphQL with Basic auth and version header", async () =>
{
    host.Reset();
    host.Braintree.Reply("{\"data\":{\"chargePaymentMethod\":{\"transaction\":{\"id\":\"dHJhbnNhY3Rpb25fYWJj\"," +
                         "\"status\":\"SUBMITTED_FOR_SETTLEMENT\"}}}}");
    var resp = await http.PostAsJsonAsync("/api/payments/braintree",
        new { nonce = "tokencc_bh_abc123_xyz", amount = 40m, orderId = "ORD-2001" });
    Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

    var req = host.Braintree.Requests.Single();
    Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("pub:priv")), req.Authorization);
    Assert.Equal("2019-01-01", req.BraintreeVersion);
    var input = JsonNode.Parse(req.Body)!["variables"]!["input"]!;
    Assert.Equal("tokencc_bh_abc123_xyz", input["paymentMethodId"]!.GetValue<string>());
    Assert.Equal("40.00", input["transaction"]!["amount"]!.GetValue<string>());
});

Test("braintree: GraphQL error is returned as 422", async () =>
{
    host.Braintree.Reply("{\"errors\":[{\"message\":\"Unknown or expired payment method ID.\"}],\"data\":null}");
    var resp = await http.PostAsJsonAsync("/api/payments/braintree", new { nonce = "expired", amount = 1m, orderId = "O2" });
    Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
});

Test("api log: card data echoed by a provider is masked before it is stored", async () =>
{
    host.Reset();
    host.Braintree.Reply("{\"errors\":[{\"message\":\"card 4111111111111111 cvv=123 rejected\"}]}");
    await http.PostAsJsonAsync("/api/payments/braintree", new { nonce = "n1", amount = 1m, orderId = "O3" });
    var joined = string.Join("\n", host.ApiLog.Entries);
    Assert.DoesNotContain("4111111111111111", joined);
    Assert.Contains("************1111", joined);
    Assert.Contains("cvv=***", joined);
});

Test("headers: CSP limits scripts and frames to the two providers", async () =>
{
    var resp = await http.GetAsync("/braintree.html");
    Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    var csp = resp.Headers.GetValues("Content-Security-Policy").Single();
    Assert.Contains("frame-src https://assets.braintreegateway.com", csp);
    Assert.Contains("frame-ancestors 'none'", csp);
    Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
});

Test("pages: card inputs on the Accept.js page have no name attribute", async () =>
{
    var html = await http.GetStringAsync("/authorize-net.html");
    foreach (var id in new[] { "cc-number", "cc-month", "cc-year", "cc-cvv" })
    {
        var tag = html[html.IndexOf($"id=\"{id}\"", StringComparison.Ordinal)..];
        tag = tag[..tag.IndexOf('>')];
        Assert.DoesNotContain("name=", tag);
    }
});

// ---------------------------------------------------------------- scanner
Sync("scanner: legacy site inventory", () =>
{
    var report = Scanner.Scan(Path.Combine(root, "samples/legacy-site")).ToDictionary(r => r.File);
    Assert.Equal("RAW", report["Checkout.aspx"].Status);
    Assert.Equal("RAW", report["PayBalance.aspx"].Status);
    Assert.Equal("RAW", report["Views/Billing/Pay.cshtml"].Status);
    Assert.Equal("RAW", report["OldPayment.aspx"].Status);
    Assert.Equal(0, report["OldPayment.aspx"].ReferencedBy);
    Assert.Equal("TOKENIZED", report["AcceptPay.aspx"].Status);
    Assert.Equal("REVIEW", report["Views/Billing/Draft.cshtml"].Status);
    Assert.False(report.ContainsKey("Profile.aspx"), "pages without card fields are not listed");
});

Sync("scanner: the demo site has no RAW pages", () =>
{
    var report = Scanner.Scan(Path.Combine(root, "src/PaymentsDemo/wwwroot"));
    Assert.Equal(2, report.Count);
    Assert.True(report.All(r => r.Status == "TOKENIZED"), "all demo pages must be tokenized");
});

// ---------------------------------------------------------------- run
int failed = 0;
foreach (var (name, body) in tests)
{
    try
    {
        await body();
        Console.WriteLine($"ok   {name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL {name}\n     {ex.Message}");
    }
}
Console.WriteLine($"\n{tests.Count - failed}/{tests.Count} passed");
return failed == 0 ? 0 : 1;

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "PciRemediationLab.sln"))) dir = dir.Parent;
    return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
}

sealed class StubHandler : HttpMessageHandler
{
    public sealed record Captured(string Body, string? Authorization, string? BraintreeVersion);

    private string _reply = "{}";
    public List<Captured> Requests { get; } = [];

    public void Reply(string json) => _reply = json;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        request.Headers.TryGetValues("Braintree-Version", out var version);
        lock (Requests) Requests.Add(new Captured(body, request.Headers.Authorization?.ToString(), version?.FirstOrDefault()));
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(_reply, Encoding.UTF8, "application/json"),
        };
    }
}

sealed class TestHost : IAsyncDisposable
{
    public const string TransactionKey = "TXNKEY-SECRET-123";
    public required StubHandler AuthNet { get; init; }
    public required StubHandler Braintree { get; init; }
    public required WebApplication App { get; init; }
    public required HttpClient Client { get; init; }
    public IApiLog ApiLog => App.Services.GetRequiredService<IApiLog>();

    public void Reset()
    {
        AuthNet.Requests.Clear();
        Braintree.Requests.Clear();
    }

    public static async Task<TestHost> StartAsync(string contentRoot)
    {
        var authNet = new StubHandler();
        var braintree = new StubHandler();
        var app = PaymentsDemo.App.Build(["--urls", "http://127.0.0.1:0", "--Logging:LogLevel:Default=Warning"], services =>
        {
            services.AddSingleton(new GatewayOptions
            {
                AuthorizeNetApiLoginId = "login", AuthorizeNetTransactionKey = TransactionKey,
                AuthorizeNetPublicClientKey = "client", BraintreePublicKey = "pub", BraintreePrivateKey = "priv",
            });
            services.AddHttpClient<AuthorizeNetGateway>().ConfigurePrimaryHttpMessageHandler(() => authNet);
            services.AddHttpClient<BraintreeGateway>().ConfigurePrimaryHttpMessageHandler(() => braintree);
        }, contentRoot);
        // A stand-in for an old server-side checkout page: it must never be reached with card data.
        app.MapPost("/legacy/checkout", () => Results.Ok("legacy handler reached"));
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        return new TestHost
        {
            App = app, AuthNet = authNet, Braintree = braintree,
            Client = new HttpClient { BaseAddress = new Uri(address) },
        };
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
    }
}

static class Assert
{
    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"expected <{expected}> but got <{actual}>");
    }

    public static void True(bool value, string message = "expected true")
    {
        if (!value) throw new Exception(message);
    }

    public static void False(bool value, string message = "expected false")
    {
        if (value) throw new Exception(message);
    }

    public static void Contains(string needle, string haystack)
    {
        if (!haystack.Contains(needle, StringComparison.Ordinal))
            throw new Exception($"expected to find <{needle}> in <{Trim(haystack)}>");
    }

    public static void DoesNotContain(string needle, string haystack)
    {
        if (haystack.Contains(needle, StringComparison.Ordinal))
            throw new Exception($"did not expect <{needle}> in <{Trim(haystack)}>");
    }

    private static string Trim(string s) => s.Length > 300 ? s[..300] + "..." : s;
}
