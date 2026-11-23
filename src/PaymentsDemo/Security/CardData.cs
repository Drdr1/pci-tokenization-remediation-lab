using System.Text;

namespace PaymentsDemo.Security;

/// <summary>
/// Finds and redacts card data in free text (request bodies, API log entries).
///
/// The rules are deliberately simple and are mirrored character for character
/// by sql/00_functions.sql, so the application and the database cleanup mask
/// the same input in exactly the same way (tests/fixtures/redaction_cases.json
/// is run against both).
///
/// PAN: 13-19 digits, optionally split by single spaces or dashes between
/// digits, first digit 2-6, passing the Luhn check, and not touching other
/// digits on either side. Every digit except the last four becomes '*';
/// separators are kept.
///
/// CVV: a value of exactly 3 or 4 digits under one of the CVV key names, in
/// JSON ("cvv":"123" or "cvv":123), form/query (cvv=123) or XML
/// (&lt;cvv&gt;123&lt;/cvv&gt;) form. Key names match case-insensitively.
/// The value becomes "***".
/// </summary>
public static class CardData
{
    public static readonly string[] CvvKeys =
    [
        "cvv", "cvv2", "cvc", "cvc2", "cardcode", "card_code", "securitycode", "security_code",
    ];

    public static bool ContainsCardData(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return Redact(text) != text;
    }

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
        return RedactCvv(RedactPans(text));
    }

    public static bool PassesLuhn(ReadOnlySpan<char> digits)
    {
        int sum = 0;
        bool dbl = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (dbl)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static bool IsDigit(char c) => c is >= '0' and <= '9';

    private static bool IsSep(char c) => c is ' ' or '-';

    private static string RedactPans(string s)
    {
        var chars = s.ToCharArray();
        int n = chars.Length;
        int i = 0;
        while (i < n)
        {
            if (!IsDigit(chars[i]) || (i > 0 && IsDigit(chars[i - 1])))
            {
                i++;
                continue;
            }

            // Collect a run of digits with single separators between digits.
            var positions = new List<int>();
            var digits = new StringBuilder();
            int j = i;
            while (j < n)
            {
                if (IsDigit(chars[j]))
                {
                    positions.Add(j);
                    digits.Append(chars[j]);
                    j++;
                }
                else if (IsSep(chars[j]) && j + 1 < n && IsDigit(chars[j + 1]) && j > i && IsDigit(chars[j - 1]))
                {
                    j++;
                }
                else
                {
                    break;
                }
            }

            int count = digits.Length;
            if (count >= 13 && count <= 19 && digits[0] >= '2' && digits[0] <= '6'
                && PassesLuhn(digits.ToString()))
            {
                for (int k = 0; k < count - 4; k++) chars[positions[k]] = '*';
            }
            i = j;
        }
        return new string(chars);
    }

    private static string RedactCvv(string s)
    {
        foreach (var key in CvvKeys)
        {
            s = RedactJsonCvv(s, key);
            s = RedactFormCvv(s, key);
            s = RedactXmlCvv(s, key);
        }
        return s;
    }

    // Returns the index just past a run of 3-4 digits starting at 'start', or -1.
    private static int CvvEnd(string s, int start)
    {
        int j = start;
        while (j < s.Length && IsDigit(s[j]) && j - start < 5) j++;
        int len = j - start;
        return len is 3 or 4 ? j : -1;
    }

    private static string ReplaceRange(string s, int start, int end) =>
        string.Concat(s.AsSpan(0, start), "***", s.AsSpan(end));

    private static string RedactJsonCvv(string s, string key)
    {
        string marker = "\"" + key + "\"";
        int from = 0;
        while (true)
        {
            int at = s.IndexOf(marker, from, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return s;
            int j = at + marker.Length;
            while (j < s.Length && s[j] == ' ') j++;
            if (j >= s.Length || s[j] != ':') { from = at + 1; continue; }
            j++;
            while (j < s.Length && s[j] == ' ') j++;
            bool quoted = j < s.Length && s[j] == '"';
            if (quoted) j++;
            int end = CvvEnd(s, j);
            bool ok = end > 0 && (quoted ? end < s.Length && s[end] == '"' : end >= s.Length || !IsDigit(s[end]));
            if (ok)
            {
                s = ReplaceRange(s, j, end);
                from = j + 3;
            }
            else
            {
                from = at + 1;
            }
        }
    }

    private static string RedactFormCvv(string s, string key)
    {
        string marker = key + "=";
        int from = 0;
        while (true)
        {
            int at = s.IndexOf(marker, from, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return s;
            bool boundary = at == 0 || s[at - 1] is '&' or '?' or ' ' or '\n' or '\r' or '\t';
            int j = at + marker.Length;
            int end = CvvEnd(s, j);
            if (boundary && end > 0 && (end >= s.Length || !IsDigit(s[end])))
            {
                s = ReplaceRange(s, j, end);
                from = j + 3;
            }
            else
            {
                from = at + 1;
            }
        }
    }

    private static string RedactXmlCvv(string s, string key)
    {
        string open = "<" + key + ">";
        string close = "</";
        int from = 0;
        while (true)
        {
            int at = s.IndexOf(open, from, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return s;
            int j = at + open.Length;
            int end = CvvEnd(s, j);
            if (end > 0 && string.CompareOrdinal(s, end, close, 0, close.Length) == 0)
            {
                s = ReplaceRange(s, j, end);
                from = j + 3;
            }
            else
            {
                from = at + 1;
            }
        }
    }
}
