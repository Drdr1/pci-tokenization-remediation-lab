// CardFieldScanner: inventories every page that contains card inputs.
//
//   dotnet run --project tools/CardFieldScanner -- <site-root> [--fail-on-raw]
//
// Output is CSV: file, status, card_controls, tokenizer, referenced_by.
//   RAW        a card number or CVV control that posts to our server
//              (asp:TextBox runat=server, Html.TextBoxFor/asp-for, or an <input> with a name)
//   TOKENIZED  card inputs exist only client-side or in hosted iframes, and the page
//              uses Accept.js or Braintree Hosted Fields
//   REVIEW     client-only card inputs but no tokenizer on the page
// referenced_by counts other files that mention this page's file name; 0 marks a
// page nothing links to, which is a candidate for retirement instead of remediation.

using System.Text;
using System.Text.RegularExpressions;

var argsList = args.ToList();
bool failOnRaw = argsList.Remove("--fail-on-raw");
if (argsList.Count != 1 || !Directory.Exists(argsList[0]))
{
    Console.Error.WriteLine("usage: CardFieldScanner <site-root> [--fail-on-raw]");
    return 2;
}

var report = Scanner.Scan(argsList[0]);
Console.Write(Scanner.ToCsv(report));
int raw = report.Count(r => r.Status == "RAW");
Console.Error.WriteLine($"{report.Count} page(s) with card inputs: {raw} RAW, " +
                        $"{report.Count(r => r.Status == "TOKENIZED")} TOKENIZED, " +
                        $"{report.Count(r => r.Status == "REVIEW")} REVIEW, " +
                        $"{report.Count(r => r.ReferencedBy == 0)} unreferenced");
return failOnRaw && raw > 0 ? 1 : 0;

public sealed record PageReport(string File, string Status, string[] CardControls, string Tokenizer, int ReferencedBy);

public static partial class Scanner
{
    private static readonly string[] PageExtensions =
        [".aspx", ".ascx", ".master", ".cshtml", ".vbhtml", ".razor", ".html", ".htm"];

    private static readonly string[] ReferenceExtensions =
        [.. PageExtensions, ".cs", ".vb", ".js", ".config", ".sitemap"];

    // Identifier that names a card number or CVV field.
    private const string CardWord =
        @"(?:card_?-?(?:no|num|number)|cc_?-?(?:no|num|number)|credit_?-?card(?:_?-?number)?|\bpan\b|" +
        @"cvv2?|cvc2?|card_?-?code|security_?-?code)";

    [GeneratedRegex(@"<asp:TextBox\b[^>]*\bID\s*=\s*""(?<id>[^""]*" + CardWord + @"[^""]*)""[^>]*>",
        RegexOptions.IgnoreCase)]
    private static partial Regex AspTextBox();

    [GeneratedRegex(@"Html\.(?:TextBoxFor|EditorFor|PasswordFor|HiddenFor)\s*\(\s*\w+\s*=>\s*\w+\.(?<id>\w*" +
                    CardWord + @"\w*)", RegexOptions.IgnoreCase)]
    private static partial Regex MvcHelper();

    [GeneratedRegex(@"asp-for\s*=\s*""(?<id>[^""]*" + CardWord + @"[^""]*)""", RegexOptions.IgnoreCase)]
    private static partial Regex TagHelper();

    [GeneratedRegex(@"<input\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex InputTag();

    [GeneratedRegex(@"\bname\s*=\s*[""'](?<v>[^""']*)[""']", RegexOptions.IgnoreCase)]
    private static partial Regex NameAttr();

    [GeneratedRegex(@"\bid\s*=\s*[""'](?<v>[^""']*)[""']", RegexOptions.IgnoreCase)]
    private static partial Regex IdAttr();

    [GeneratedRegex(@"\bautocomplete\s*=\s*[""']cc-(?:number|csc)[""']", RegexOptions.IgnoreCase)]
    private static partial Regex CardAutocomplete();

    [GeneratedRegex(CardWord, RegexOptions.IgnoreCase)]
    private static partial Regex CardIdentifier();

    [GeneratedRegex(@"Accept\.js|Accept\.dispatchData|AcceptUI|AuthorizeNetPayments\.mount", RegexOptions.IgnoreCase)]
    private static partial Regex AcceptMarker();

    [GeneratedRegex(@"hosted-fields(?:\.min)?\.js|hostedFields\.create|braintree-payments\.js|BraintreePayments\.mount",
        RegexOptions.IgnoreCase)]
    private static partial Regex BraintreeMarker();

    public static List<PageReport> Scan(string root)
    {
        var files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .ToList();
        var texts = files
            .Where(f => ReferenceExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()))
            .ToDictionary(f => f, File.ReadAllText);

        var results = new List<PageReport>();
        foreach (var (file, text) in texts.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (!PageExtensions.Contains(Path.GetExtension(file).ToLowerInvariant())) continue;
            var (rawControls, clientControls) = FindControls(text);
            if (rawControls.Count == 0 && clientControls.Count == 0)
            {
                // Hosted Fields pages have no card inputs at all, only iframe containers.
                if (!BraintreeMarker().IsMatch(text)) continue;
                clientControls.Add("hosted-iframes");
            }

            var tokenizer = string.Join("+", new[]
            {
                AcceptMarker().IsMatch(text) ? "accept.js" : null,
                BraintreeMarker().IsMatch(text) ? "braintree-hosted-fields" : null,
            }.Where(x => x is not null));

            string status = rawControls.Count > 0 ? "RAW" : tokenizer.Length > 0 ? "TOKENIZED" : "REVIEW";
            var name = Path.GetFileName(file);
            int refs = texts.Count(kv => kv.Key != file
                                         && kv.Value.Contains(name, StringComparison.OrdinalIgnoreCase));
            results.Add(new PageReport(Path.GetRelativePath(root, file).Replace('\\', '/'), status,
                [.. rawControls.Select(c => "raw:" + c), .. clientControls.Select(c => "client:" + c)],
                tokenizer.Length > 0 ? tokenizer : "none", refs));
        }
        return results;
    }

    private static (List<string> Raw, List<string> Client) FindControls(string text)
    {
        var raw = new List<string>();
        var client = new List<string>();
        foreach (Match m in AspTextBox().Matches(text))
        {
            if (m.Value.Contains("runat", StringComparison.OrdinalIgnoreCase)) raw.Add(m.Groups["id"].Value);
        }
        foreach (Match m in MvcHelper().Matches(text)) raw.Add(m.Groups["id"].Value);
        foreach (Match m in TagHelper().Matches(text)) raw.Add(m.Groups["id"].Value);

        foreach (Match m in InputTag().Matches(text))
        {
            var tag = m.Value;
            var name = NameAttr().Match(tag);
            var id = IdAttr().Match(tag);
            bool cardish = CardAutocomplete().IsMatch(tag)
                           || (name.Success && CardIdentifier().IsMatch(name.Groups["v"].Value))
                           || (id.Success && CardIdentifier().IsMatch(id.Groups["v"].Value));
            if (!cardish) continue;
            var label = name.Success ? name.Groups["v"].Value : id.Success ? id.Groups["v"].Value : "input";
            if (name.Success && name.Groups["v"].Value.Length > 0) raw.Add(label);
            else client.Add(label);
        }
        return (raw.Distinct().ToList(), client.Distinct().ToList());
    }

    public static string ToCsv(IEnumerable<PageReport> rows)
    {
        var sb = new StringBuilder("file,status,card_controls,tokenizer,referenced_by\n");
        foreach (var r in rows)
        {
            sb.Append(r.File).Append(',').Append(r.Status).Append(',')
              .Append(string.Join(' ', r.CardControls)).Append(',').Append(r.Tokenizer).Append(',')
              .Append(r.ReferencedBy).Append('\n');
        }
        return sb.ToString();
    }
}
