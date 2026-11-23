using System.Text.RegularExpressions;
using PaymentsDemo.Payments;
using PaymentsDemo.Security;

namespace PaymentsDemo;

public sealed record AcceptOpaqueData(string? DataDescriptor, string? DataValue);
public sealed record AuthorizeNetChargeRequest(AcceptOpaqueData? OpaqueData, decimal Amount, string? InvoiceNumber);
public sealed record BraintreeChargeRequest(string? Nonce, decimal Amount, string? OrderId);

public static partial class App
{
    // Card iframes and scripts come only from the two providers. Accept.js posts the
    // card data from the browser straight to Authorize.Net; Hosted Fields renders
    // the inputs inside Braintree-hosted iframes.
    public const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self' https://js.authorize.net https://jstest.authorize.net https://js.braintreegateway.com; " +
        "frame-src https://assets.braintreegateway.com; " +
        "connect-src 'self' https://api2.authorize.net https://apitest.authorize.net " +
        "https://payments.braintree-api.com https://payments.sandbox.braintree-api.com " +
        "https://api.braintreegateway.com https://api.sandbox.braintreegateway.com " +
        "https://client-analytics.braintreegateway.com https://client-analytics.sandbox.braintreegateway.com; " +
        "img-src 'self' data:; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    public static WebApplication Build(string[] args, Action<IServiceCollection>? overrides = null,
        string? contentRoot = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = contentRoot,
        });
        builder.Services.AddSingleton(GatewayOptions.FromEnvironment());
        builder.Services.AddSingleton<IApiLog, InMemoryApiLog>();
        builder.Services.AddHttpClient<AuthorizeNetGateway>();
        builder.Services.AddHttpClient<BraintreeGateway>();
        overrides?.Invoke(builder.Services);

        var app = builder.Build();
        app.Use(async (ctx, next) =>
        {
            var h = ctx.Response.Headers;
            h.ContentSecurityPolicy = ContentSecurityPolicy;
            h.XContentTypeOptions = "nosniff";
            h["Referrer-Policy"] = "no-referrer";
            await next();
        });
        app.UseMiddleware<CardDataGuard>();
        app.UseDefaultFiles();
        app.UseStaticFiles();
        MapPaymentApi(app);
        return app;
    }

    public static void MapPaymentApi(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/payments/config", (GatewayOptions o) => Results.Ok(new
        {
            authorizeNet = new
            {
                apiLoginId = o.AuthorizeNetApiLoginId,
                clientKey = o.AuthorizeNetPublicClientKey,
                configured = o.AuthorizeNetApiLoginId.Length > 0 && o.AuthorizeNetPublicClientKey.Length > 0,
            },
            braintree = new { configured = o.BraintreePublicKey.Length > 0 && o.BraintreePrivateKey.Length > 0 },
        }));

        app.MapGet("/api/payments/braintree/client-token", async (BraintreeGateway gw, CancellationToken ct) =>
        {
            var token = await gw.CreateClientTokenAsync(ct);
            return token is null ? Results.Problem("could not create client token", statusCode: 502)
                                 : Results.Ok(new { clientToken = token });
        });

        app.MapPost("/api/payments/authorize-net", async (AuthorizeNetChargeRequest req, AuthorizeNetGateway gw,
            CancellationToken ct) =>
        {
            var errors = new Dictionary<string, string[]>();
            if (req.OpaqueData?.DataDescriptor != AuthorizeNetGateway.AcceptDescriptor)
                errors["opaqueData.dataDescriptor"] = [$"must be {AuthorizeNetGateway.AcceptDescriptor}"];
            if (string.IsNullOrWhiteSpace(req.OpaqueData?.DataValue) || req.OpaqueData.DataValue.Length > 8192)
                errors["opaqueData.dataValue"] = ["required"];
            ValidateCommon(req.Amount, req.InvoiceNumber, 20, errors);
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var result = await gw.ChargeAsync(req.OpaqueData!.DataDescriptor!, req.OpaqueData.DataValue!,
                req.Amount, req.InvoiceNumber!, ct);
            return result.Approved ? Results.Ok(result) : Results.UnprocessableEntity(result);
        });

        app.MapPost("/api/payments/braintree", async (BraintreeChargeRequest req, BraintreeGateway gw,
            CancellationToken ct) =>
        {
            var errors = new Dictionary<string, string[]>();
            if (req.Nonce is null || !NonceShape().IsMatch(req.Nonce))
                errors["nonce"] = ["required"];
            ValidateCommon(req.Amount, req.OrderId, 255, errors);
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var result = await gw.ChargeAsync(req.Nonce!, req.Amount, req.OrderId!, ct);
            return result.Approved ? Results.Ok(result) : Results.UnprocessableEntity(result);
        });
    }

    private static void ValidateCommon(decimal amount, string? reference, int maxRef,
        Dictionary<string, string[]> errors)
    {
        if (amount <= 0 || amount > 100_000m || decimal.Round(amount, 2) != amount)
            errors["amount"] = ["must be between 0.01 and 100000.00 with at most 2 decimals"];
        if (string.IsNullOrWhiteSpace(reference) || reference.Length > maxRef || !ReferenceShape().IsMatch(reference))
            errors["reference"] = [$"required, up to {maxRef} letters, digits or -_"];
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{1,256}$")]
    private static partial Regex NonceShape();

    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex ReferenceShape();
}

public static class Program
{
    public static void Main(string[] args) => App.Build(args).Run();
}
