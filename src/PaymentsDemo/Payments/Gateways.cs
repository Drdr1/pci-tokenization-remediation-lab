using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PaymentsDemo.Security;

namespace PaymentsDemo.Payments;

public sealed record ChargeResult(bool Approved, string? TransactionId, string Message);

public sealed record GatewayOptions
{
    public string AuthorizeNetEndpoint { get; init; } = "https://apitest.authorize.net/xml/v1/request.api";
    public string AuthorizeNetApiLoginId { get; init; } = "";
    public string AuthorizeNetTransactionKey { get; init; } = "";
    public string AuthorizeNetPublicClientKey { get; init; } = "";
    public string BraintreeEndpoint { get; init; } = "https://payments.sandbox.braintree-api.com/graphql";
    public string BraintreePublicKey { get; init; } = "";
    public string BraintreePrivateKey { get; init; } = "";
    public string BraintreeVersion { get; init; } = "2019-01-01";

    public static GatewayOptions FromEnvironment() => new()
    {
        AuthorizeNetApiLoginId = Env("AUTHNET_API_LOGIN_ID"),
        AuthorizeNetTransactionKey = Env("AUTHNET_TRANSACTION_KEY"),
        AuthorizeNetPublicClientKey = Env("AUTHNET_PUBLIC_CLIENT_KEY"),
        BraintreePublicKey = Env("BRAINTREE_PUBLIC_KEY"),
        BraintreePrivateKey = Env("BRAINTREE_PRIVATE_KEY"),
    };

    private static string Env(string name) => Environment.GetEnvironmentVariable(name) ?? "";
}

/// <summary>
/// Every outbound gateway call and its response goes through here, and is
/// redacted before it is stored. This is the forward-looking fix for the
/// APILog table: even if a provider echoes card data, it is never persisted.
/// </summary>
public interface IApiLog
{
    void Write(string direction, string endpoint, string body);
    IReadOnlyList<string> Entries { get; }
}

public sealed class InMemoryApiLog : IApiLog
{
    private readonly List<string> _entries = [];
    private readonly object _lock = new();

    public void Write(string direction, string endpoint, string body)
    {
        var line = $"{DateTimeOffset.UtcNow:O} {direction} {endpoint} {CardData.Redact(body)}";
        lock (_lock) _entries.Add(line);
    }

    public IReadOnlyList<string> Entries
    {
        get { lock (_lock) return _entries.ToList(); }
    }
}

/// <summary>Charges an Authorize.Net Accept.js payment nonce (opaqueData). Never sees a card number.</summary>
public sealed class AuthorizeNetGateway(HttpClient http, GatewayOptions options, IApiLog log)
{
    public const string AcceptDescriptor = "COMMON.ACCEPT.INAPP.PAYMENT";

    public async Task<ChargeResult> ChargeAsync(string dataDescriptor, string dataValue, decimal amount,
        string invoiceNumber, CancellationToken ct)
    {
        var payload = new JsonObject
        {
            ["createTransactionRequest"] = new JsonObject
            {
                ["merchantAuthentication"] = new JsonObject
                {
                    ["name"] = options.AuthorizeNetApiLoginId,
                    ["transactionKey"] = options.AuthorizeNetTransactionKey,
                },
                ["refId"] = invoiceNumber,
                ["transactionRequest"] = new JsonObject
                {
                    ["transactionType"] = "authCaptureTransaction",
                    ["amount"] = amount.ToString("0.00", CultureInfo.InvariantCulture),
                    ["payment"] = new JsonObject
                    {
                        ["opaqueData"] = new JsonObject
                        {
                            ["dataDescriptor"] = dataDescriptor,
                            ["dataValue"] = dataValue,
                        },
                    },
                    ["order"] = new JsonObject { ["invoiceNumber"] = invoiceNumber },
                },
            },
        };
        var body = payload.ToJsonString();
        log.Write("OUT", "authorize.net", MaskSecret(body, options.AuthorizeNetTransactionKey));

        using var resp = await http.PostAsync(options.AuthorizeNetEndpoint,
            new StringContent(body, Encoding.UTF8, "application/json"), ct);
        // Authorize.Net prefixes its JSON responses with a UTF-8 byte order mark.
        var text = (await resp.Content.ReadAsStringAsync(ct)).TrimStart('﻿');
        log.Write("IN", "authorize.net", text);

        var json = JsonNode.Parse(text);
        var resultCode = json?["messages"]?["resultCode"]?.GetValue<string>();
        var tx = json?["transactionResponse"];
        var responseCode = tx?["responseCode"]?.GetValue<string>();
        var transId = tx?["transId"]?.GetValue<string>();
        bool approved = resultCode == "Ok" && responseCode == "1";
        var message = approved
            ? "approved"
            : tx?["errors"]?[0]?["errorText"]?.GetValue<string>()
              ?? json?["messages"]?["message"]?[0]?["text"]?.GetValue<string>()
              ?? "declined";
        return new ChargeResult(approved, approved ? transId : null, message);
    }

    private static string MaskSecret(string body, string secret) =>
        string.IsNullOrEmpty(secret) ? body : body.Replace(secret, "[transactionKey]");
}

/// <summary>Charges a Braintree Hosted Fields nonce through the GraphQL API. Never sees a card number.</summary>
public sealed class BraintreeGateway(HttpClient http, GatewayOptions options, IApiLog log)
{
    private const string ChargeMutation =
        "mutation Charge($input: ChargePaymentMethodInput!) { chargePaymentMethod(input: $input) " +
        "{ transaction { id status } } }";

    private const string ClientTokenMutation =
        "mutation { createClientToken(input: {}) { clientToken } }";

    public async Task<ChargeResult> ChargeAsync(string nonce, decimal amount, string orderId, CancellationToken ct)
    {
        var variables = new JsonObject
        {
            ["input"] = new JsonObject
            {
                ["paymentMethodId"] = nonce,
                ["transaction"] = new JsonObject
                {
                    ["amount"] = amount.ToString("0.00", CultureInfo.InvariantCulture),
                    ["orderId"] = orderId,
                },
            },
        };
        var json = await PostAsync(ChargeMutation, variables, ct);
        var errors = json?["errors"];
        if (errors is JsonArray { Count: > 0 } arr)
        {
            return new ChargeResult(false, null, arr[0]?["message"]?.GetValue<string>() ?? "declined");
        }
        var tx = json?["data"]?["chargePaymentMethod"]?["transaction"];
        var status = tx?["status"]?.GetValue<string>() ?? "";
        bool approved = status is "SUBMITTED_FOR_SETTLEMENT" or "SETTLING" or "SETTLED" or "AUTHORIZED";
        return new ChargeResult(approved, approved ? tx?["id"]?.GetValue<string>() : null,
            approved ? "approved" : $"status {status}");
    }

    public async Task<string?> CreateClientTokenAsync(CancellationToken ct)
    {
        var json = await PostAsync(ClientTokenMutation, null, ct);
        return json?["data"]?["createClientToken"]?["clientToken"]?.GetValue<string>();
    }

    private async Task<JsonNode?> PostAsync(string query, JsonObject? variables, CancellationToken ct)
    {
        var payload = new JsonObject { ["query"] = query };
        if (variables is not null) payload["variables"] = variables;
        var body = payload.ToJsonString();

        using var req = new HttpRequestMessage(HttpMethod.Post, options.BraintreeEndpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        var basic = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{options.BraintreePublicKey}:{options.BraintreePrivateKey}"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        req.Headers.Add("Braintree-Version", options.BraintreeVersion);
        log.Write("OUT", "braintree", body);

        using var resp = await http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        log.Write("IN", "braintree", text);
        return JsonNode.Parse(text);
    }
}

public static class Json
{
    public static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);
}
