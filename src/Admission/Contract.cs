using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DataAdmission;

internal sealed class Problem(string code) : Exception(code) { public string Code { get; } = code; }
internal static partial class Contract
{
    public const string Version = "0.1.0-preview.1", Profile = "admission-ohlc-csv-v1", Purpose = "offline-analysis";
    public const int InputLimit = 1024 * 1024, PolicyLimit = 128 * 1024, DecisionLimit = 16 * 1024;
    public const int JsonOutputLimit = 128 * 1024, TextOutputLimit = 32 * 1024, ArtifactLimit = 2 * 1024 * 1024;
    public const string VendorRevision = "eecf14a1fdeecedb55ceb6c4947ac57e70bd4a41";
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);
    public static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    [GeneratedRegex(@"\A[a-f0-9]{64}\z")] private static partial Regex HashPattern();
    [GeneratedRegex(@"\A[a-f0-9]{32}\z")] private static partial Regex NoncePattern();
    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z")] private static partial Regex LabelPattern();
    [GeneratedRegex(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z")] private static partial Regex TimePattern();
    public static string Label(string s) => LabelPattern().IsMatch(s) ? s : throw new Problem("LABEL_INVALID");
    public static string Sha(string s) => HashPattern().IsMatch(s) ? s : throw new Problem("HASH_INVALID");
    public static string Nonce(string s) => NoncePattern().IsMatch(s) ? s : throw new Problem("OWNERSHIP_INVALID");
    public static DateTimeOffset Time(string s)
    {
        if (!TimePattern().IsMatch(s) || !DateTimeOffset.TryParseExact(s, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time)) throw new Problem("UTC_TIMESTAMP_INVALID");
        return time;
    }
    public static void Fields(JsonElement e, params string[] names)
    {
        if (e.ValueKind != JsonValueKind.Object) throw new Problem("JSON_SHAPE_INVALID"); HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (var p in e.EnumerateObject()) if (!seen.Add(p.Name)) throw new Problem("JSON_DUPLICATE_KEY");
        if (!seen.SetEquals(names)) throw new Problem("JSON_FIELDS_INVALID");
    }
    public static string Text(JsonElement e, string name) => e.GetProperty(name).ValueKind == JsonValueKind.String ? e.GetProperty(name).GetString()! : throw new Problem("JSON_STRING_REQUIRED");
    public static long Integer(JsonElement e, string name)
    {
        var v = e.GetProperty(name); if (v.ValueKind != JsonValueKind.Number || v.GetRawText().Any(c => c is < '0' or > '9') || !v.TryGetInt64(out long n)) throw new Problem("INTEGER_ENCODING_INVALID"); return n;
    }
    public static JsonDocument Document(byte[] bytes, int cap)
    {
        if (bytes.Length > cap) throw new Problem("JSON_BYTE_LIMIT");
        try { return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 }); } catch (JsonException) { throw new Problem("JSON_INVALID"); }
    }
    public static string Build => System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(typeof(Contract).Assembly)?.InformationalVersion ?? "UNAVAILABLE";
}

internal sealed record Policy(string AsOf, int MaxAgeSeconds, string[] ExpectedTimestamps)
{
    public static Policy Parse(byte[] bytes)
    {
        using var d = Contract.Document(bytes, Contract.PolicyLimit); var r = d.RootElement;
        Contract.Fields(r, "schema", "profile", "purpose", "asOf", "maxAgeSeconds", "expectedTimestamps");
        if (Contract.Text(r, "schema") != "data-admission-policy-v1" || Contract.Text(r, "profile") != Contract.Profile || Contract.Text(r, "purpose") != Contract.Purpose) throw new Problem("POLICY_PROFILE_UNSUPPORTED");
        string asOf = Contract.Text(r, "asOf"); Contract.Time(asOf); long age = Contract.Integer(r, "maxAgeSeconds"); if (age > 604800) throw new Problem("AGE_LIMIT_INVALID");
        var items = r.GetProperty("expectedTimestamps"); if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() is < 1 or > 1000) throw new Problem("GRID_COUNT_INVALID");
        List<string> grid = []; string? previous = null;
        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) throw new Problem("GRID_TIMESTAMP_INVALID"); string stamp = item.GetString()!; Contract.Time(stamp);
            if (previous != null && StringComparer.Ordinal.Compare(previous, stamp) >= 0) throw new Problem("GRID_ORDER_OR_DUPLICATE_INVALID"); grid.Add(stamp); previous = stamp;
        }
        return new(asOf, (int)age, grid.ToArray());
    }
}
internal sealed record OwnerDecision(string DatasetSha256, string PolicySha256, string Purpose, string Provenance, string UseLicense)
{
    public static OwnerDecision Parse(byte[] bytes)
    {
        using var d = Contract.Document(bytes, Contract.DecisionLimit); var r = d.RootElement;
        Contract.Fields(r, "schema", "datasetSha256", "policySha256", "purpose", "ownerLabel", "evidenceRefs", "provenance", "useLicense");
        if (Contract.Text(r, "schema") != "owner-decision-v1") throw new Problem("DECISION_PROFILE_UNSUPPORTED");
        string dataset = Contract.Sha(Contract.Text(r, "datasetSha256")), policy = Contract.Sha(Contract.Text(r, "policySha256")), purpose = Contract.Label(Contract.Text(r, "purpose"));
        Contract.Label(Contract.Text(r, "ownerLabel")); var refs = r.GetProperty("evidenceRefs");
        if (refs.ValueKind != JsonValueKind.Array || refs.GetArrayLength() > 8) throw new Problem("DECISION_REFERENCE_LIMIT"); HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (var item in refs.EnumerateArray()) if (item.ValueKind != JsonValueKind.String || !seen.Add(Contract.Label(item.GetString()!))) throw new Problem("DECISION_REFERENCE_INVALID");
        string provenance = Contract.Text(r, "provenance"), license = Contract.Text(r, "useLicense");
        if (provenance is not ("allow" or "deny" or "unknown") || license is not ("allow" or "deny" or "unknown")) throw new Problem("DECISION_VALUE_INVALID");
        return new(dataset, policy, purpose, provenance, license);
    }
}
