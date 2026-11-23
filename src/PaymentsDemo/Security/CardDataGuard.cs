using System.Text;

namespace PaymentsDemo.Security;

/// <summary>
/// Rejects any request that carries card data to our server: a PAN anywhere
/// in the query string or body, a CVV value, or a non-empty field whose name
/// says it is a card number. After the tokenization work no page should send
/// these, so a hit means a page was missed or has regressed. The event is
/// logged with the path and reason only, never the value.
/// </summary>
public sealed class CardDataGuard(RequestDelegate next, ILogger<CardDataGuard> logger)
{
    public const int MaxInspectedBytes = 1024 * 1024;

    private static readonly string[] CardFieldNames =
    [
        "cardnumber", "card_number", "ccnumber", "cc_number", "ccnum", "creditcard", "credit_card",
        "creditcardnumber", "txtcardnumber", "pan",
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        var reason = await FindCardDataAsync(context.Request);
        if (reason is not null)
        {
            logger.LogWarning("Blocked card data on {Method} {Path}: {Reason}",
                context.Request.Method, context.Request.Path, reason);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new { error = "card_data_not_accepted", reason });
            return;
        }
        await next(context);
    }

    public static async Task<string?> FindCardDataAsync(HttpRequest request)
    {
        var query = Uri.UnescapeDataString(request.QueryString.Value ?? "");
        var hit = Inspect(query, "query string");
        if (hit is not null) return hit;

        if (request.ContentLength is 0 || !(HttpMethods.IsPost(request.Method)
                                             || HttpMethods.IsPut(request.Method)
                                             || HttpMethods.IsPatch(request.Method)))
        {
            return null;
        }

        request.EnableBuffering();
        var buffer = new byte[MaxInspectedBytes];
        int read = 0, n;
        while (read < buffer.Length
               && (n = await request.Body.ReadAsync(buffer.AsMemory(read, buffer.Length - read))) > 0)
        {
            read += n;
        }
        request.Body.Position = 0;
        var body = Encoding.UTF8.GetString(buffer, 0, read);
        if (request.ContentType?.StartsWith("application/x-www-form-urlencoded",
                StringComparison.OrdinalIgnoreCase) == true)
        {
            body = Uri.UnescapeDataString(body.Replace('+', ' '));
        }
        return Inspect(body, "body");
    }

    private static string? Inspect(string text, string where)
    {
        if (text.Length == 0) return null;
        if (CardData.ContainsCardData(text)) return $"card number or CVV in {where}";
        foreach (var field in CardFieldNames)
        {
            if (HasNonEmptyField(text, field)) return $"card field '{field}' in {where}";
        }
        return null;
    }

    // Matches  field=value  (form/query) and  "field":"value"  (JSON) with a non-empty value.
    private static bool HasNonEmptyField(string text, string field)
    {
        var form = field + "=";
        int at = 0;
        while ((at = text.IndexOf(form, at, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            bool boundary = at == 0 || text[at - 1] is '&' or '?';
            int v = at + form.Length;
            if (boundary && v < text.Length && text[v] != '&') return true;
            at++;
        }

        var json = "\"" + field + "\"";
        at = 0;
        while ((at = text.IndexOf(json, at, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            int j = at + json.Length;
            while (j < text.Length && text[j] == ' ') j++;
            if (j < text.Length && text[j] == ':')
            {
                j++;
                while (j < text.Length && text[j] == ' ') j++;
                if (j < text.Length && !text.AsSpan(j).StartsWith("\"\"") && !text.AsSpan(j).StartsWith("null"))
                {
                    return true;
                }
            }
            at++;
        }
        return false;
    }
}
