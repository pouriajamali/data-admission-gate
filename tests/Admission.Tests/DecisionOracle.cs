using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using App = DataAdmission.Program;

// W2 source-only draft: UNTESTED until separately approved native execution.
// Expected decisions/text are literal oracle data, never product fixture output.
internal static class DecisionOracle
{
    private const string Csv = "timestamp,open,high,low,close,volume\n2026-01-01T00:02:00Z,100.00,102.00,99.00,101.00,5\n";
    private const string Policy = "{\"schema\":\"data-admission-policy-v1\",\"profile\":\"admission-ohlc-csv-v1\",\"purpose\":\"offline-analysis\",\"asOf\":\"2026-01-01T00:03:00Z\",\"maxAgeSeconds\":60,\"expectedTimestamps\":[\"2026-01-01T00:02:00Z\"]}\n";
    private const string MechanicalText =
        "rowQuality PASS; basis PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY; reason NO_QUARANTINED_ROWS\n" +
        "coverage PASS; basis DECLARED_GRID_ONLY; reason EXACT_ACCEPTED_GRID_AGREEMENT\n" +
        "freshness PASS; basis DECLARED_ASOF_ONLY; reason AGE_WITHIN_DECLARED_THRESHOLD\n";
    private const string ContextAndLimits =
        "Freshness context: asOf 2026-01-01T00:03:00Z; latestAccepted 2026-01-01T00:02:00Z; ageSeconds 60; thresholdSeconds 60\n" +
        "Decision meaning: offline policy only; PASS is not authenticity, legal-rights or actual-source-freshness proof.\n" +
        "Coverage DECLARED_GRID_ONLY; freshness DECLARED_ASOF_ONLY.\n" +
        "Owner basis is an assertion, not verified identity/authenticity/legal rights.\n" +
        "Identity/authenticity/legal rights/external completeness NOT_PROVEN.\n" +
        "CSV row artifacts may contain input values; keep them private.\n" +
        "Original reusable software MIT; upstream notices retained.\n";

    private sealed record Vector(string Id, string ProvenanceValue, string UseValue, bool Ack, bool ReusePositive,
        string Outcome, int Exit, string ProvenanceStatus, string UseStatus, string Basis,
        string ProvenanceReason, string UseReason, string OwnerText);

    public static void Run(string root, Action<string, Action> test)
    {
        Vector[] vectors =
        [
            new("ORACLE-01", "unknown", "allow", true, false, "HOLD", 2, "UNKNOWN", "PASS", "OWNER_DECISION_ACCEPTED",
                "OWNER_ASSERTION_UNKNOWN", "OWNER_ASSERTION_ALLOW",
                "provenance UNKNOWN; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_UNKNOWN\nuseLicense PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\n"),
            new("ORACLE-02", "allow", "allow", true, false, "ADMIT", 0, "PASS", "PASS", "OWNER_DECISION_ACCEPTED",
                "OWNER_ASSERTION_ALLOW", "OWNER_ASSERTION_ALLOW",
                "provenance PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\nuseLicense PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\n"),
            new("ORACLE-03", "allow", "unknown", true, false, "HOLD", 2, "PASS", "UNKNOWN", "OWNER_DECISION_ACCEPTED",
                "OWNER_ASSERTION_ALLOW", "OWNER_ASSERTION_UNKNOWN",
                "provenance PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\nuseLicense UNKNOWN; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_UNKNOWN\n"),
            new("ORACLE-04", "allow", "allow", false, true, "HOLD", 2, "UNKNOWN", "UNKNOWN", "UNACKNOWLEDGED_OWNER_ASSERTION",
                "EXPLICIT_ACK_REQUIRED", "EXPLICIT_ACK_REQUIRED",
                "provenance UNKNOWN; basis UNACKNOWLEDGED_OWNER_ASSERTION; reason EXPLICIT_ACK_REQUIRED\nuseLicense UNKNOWN; basis UNACKNOWLEDGED_OWNER_ASSERTION; reason EXPLICIT_ACK_REQUIRED\n")
        ];
        Dictionary<string, string>? positiveSnapshot = null;
        foreach (var vector in vectors)
        {
            test(vector.Id, () =>
            {
                string bundle = Path.Combine(root, vector.ReusePositive ? "ORACLE-02-bundle" : vector.Id + "-bundle");
                if (!vector.ReusePositive)
                    CreateBundle(bundle, vector.ProvenanceValue, vector.UseValue);
                var before = Snapshot(bundle);
                if (vector.Id == "ORACLE-02")
                    positiveSnapshot = before;
                if (vector.ReusePositive)
                    Require(positiveSnapshot != null && Same(before, positiveSnapshot), "ACK_CONTROL_EXACT_POSITIVE_BYTES");

                string report = Path.Combine(root, vector.Id + "-report");
                Require(!Directory.Exists(report) && !File.Exists(report), "FRESH_ORACLE_REPORT");
                var arguments = vector.Ack
                    ? new[] { "assess", bundle, report, "--ack-owner-decision" }
                    : new[] { "assess", bundle, report };
                var original = Console.Out;
                using var stdout = new StringWriter();
                int exit;
                try
                {
                    Console.SetOut(stdout);
                    exit = App.Main(arguments);
                }
                finally
                {
                    Console.SetOut(original);
                }
                Require(exit == vector.Exit, "LITERAL_EXIT");
                using var actual = JsonDocument.Parse(stdout.ToString());
                var r = actual.RootElement;
                Require(r.GetProperty("complete").GetBoolean() && r.GetProperty("decisionBindingMatches").GetBoolean(), "COMPLETE_BOUND_DECISION");
                Require(r.GetProperty("ownerDecisionAcknowledged").GetBoolean() == vector.Ack, "INVOCATION_ACK");
                Equal(r, "schema", "data-admission-report-v1");
                Equal(r, "version", "0.1.0-preview.2");
                Equal(r, "profile", "admission-ohlc-csv-v1");
                Equal(r, "purpose", "offline-analysis");
                Equal(r, "outcome", vector.Outcome);
                Require(r.GetProperty("exitCode").GetInt32() == vector.Exit, "JSON_EXIT");
                Axis(r, "rowQuality", "PASS", "PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY", "NO_QUARANTINED_ROWS");
                Axis(r, "coverage", "PASS", "DECLARED_GRID_ONLY", "EXACT_ACCEPTED_GRID_AGREEMENT");
                Axis(r, "freshness", "PASS", "DECLARED_ASOF_ONLY", "AGE_WITHIN_DECLARED_THRESHOLD");
                Axis(r, "provenance", vector.ProvenanceStatus, vector.Basis, vector.ProvenanceReason);
                Axis(r, "useLicense", vector.UseStatus, vector.Basis, vector.UseReason);
                var coverage = r.GetProperty("coverageDetails");
                Require(coverage.GetProperty("expected").GetInt32() == 1 && coverage.GetProperty("accepted").GetInt32() == 1, "ONE_LITERAL_SLOT");
                foreach (string name in new[] { "excludedQuarantined", "missing", "unexpected", "duplicates", "nonAscending" })
                    Require(coverage.GetProperty(name).GetInt32() == 0, "ZERO_" + name);
                Require(coverage.GetProperty("diagnosticCodes").GetArrayLength() == 0, "NO_GRID_DIAGNOSTICS");
                Equal(coverage, "scope", "DECLARED_GRID_ONLY");
                Equal(coverage, "externalCompleteness", "NOT_PROVEN");
                var freshness = r.GetProperty("freshnessDetails");
                Equal(freshness, "asOf", "2026-01-01T00:03:00Z");
                Equal(freshness, "latestAccepted", "2026-01-01T00:02:00Z");
                Require(freshness.GetProperty("ageSeconds").GetInt64() == 60 && freshness.GetProperty("thresholdSeconds").GetInt32() == 60, "LITERAL_AGE_THRESHOLD");
                Equal(freshness, "clockAccuracy", "NOT_PROVEN");
                Equal(freshness, "actualSourceFreshness", "NOT_PROVEN");
                foreach (string name in new[] { "identity", "authenticity", "legalRights" })
                    Equal(r, name, "NOT_PROVEN");
                Equal(r, "csvSourceProvenance", "UNVERIFIED");
                Equal(r, "originalSoftwareLicense", "MIT");
                Equal(r, "dataSha256", before["input.csv"]);
                Equal(r, "policySha256", before["policy.json"]);
                Equal(r, "decisionSha256", before["owner-decision.json"]);

                string expectedText = "Data Admission Gate: " + vector.Outcome + "\n" +
                    "Profile admission-ohlc-csv-v1; purpose offline-analysis\n" +
                    "Row quality PASS; coverage PASS; freshness PASS; provenance " + vector.ProvenanceStatus + "; useLicense " + vector.UseStatus + "\n" +
                    MechanicalText + vector.OwnerText + ContextAndLimits;
                byte[] jsonBytes = File.ReadAllBytes(Path.Combine(report, "summary.json"));
                byte[] textBytes = File.ReadAllBytes(Path.Combine(report, "summary.txt"));
                Require(Encoding.UTF8.GetString(textBytes) == expectedText, "LITERAL_FULL_TEXT_REPORT");
                using var saved = JsonDocument.Parse(jsonBytes);
                Require(saved.RootElement.GetRawText() == r.GetRawText(), "CLI_AND_SAVED_JSON_AGREE");
                Require(Directory.GetFiles(report, "summary.json").Length == 1 && Directory.GetFiles(report, "*.pending").Length == 0, "ONE_FINAL_NO_PENDING");
                Require(jsonBytes.Length <= 128 * 1024 && textBytes.Length <= 32 * 1024, "MAIN_REPORT_CAPS");
                Require(Directory.EnumerateFiles(Path.Combine(report, "csv-private")).Sum(path => new FileInfo(path).Length) <= 2 * 1024 * 1024, "PRIVATE_ARTIFACT_CAP");
                string main = Encoding.UTF8.GetString(jsonBytes) + expectedText;
                Require(!main.Contains("ORACLE_SYNTHETIC_OWNER", StringComparison.Ordinal) && !main.Contains("100.00", StringComparison.Ordinal) && !main.Contains(root, StringComparison.Ordinal), "NO_PRIVATE_VALUES_IN_MAIN");
                Require(Same(before, Snapshot(bundle)), "INPUT_BYTES_AND_MEMBERS_UNCHANGED");
            });
        }
    }

    private static void CreateBundle(string path, string provenance, string useLicense)
    {
        Require(!Directory.Exists(path) && !File.Exists(path), "FRESH_LITERAL_BUNDLE");
        Directory.CreateDirectory(path);
        byte[] csv = Encoding.UTF8.GetBytes(Csv), policy = Encoding.UTF8.GetBytes(Policy);
        File.WriteAllBytes(Path.Combine(path, "input.csv"), csv);
        File.WriteAllBytes(Path.Combine(path, "policy.json"), policy);
        var assertion = new
        {
            schema = "owner-decision-v1",
            datasetSha256 = Sha(csv),
            policySha256 = Sha(policy),
            purpose = "offline-analysis",
            ownerLabel = "ORACLE_SYNTHETIC_OWNER",
            evidenceRefs = new[] { "LABEL_ONLY_NOT_AUTHENTICATED" },
            provenance,
            useLicense
        };
        File.WriteAllBytes(Path.Combine(path, "owner-decision.json"), Encoding.UTF8.GetBytes(JsonSerializer.Serialize(assertion) + "\n"));
    }

    private static Dictionary<string, string> Snapshot(string path)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(path))
            result.Add(Path.GetFileName(file), Sha(File.ReadAllBytes(file)));
        Require(result.Count == 3 && result.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(new[] { "input.csv", "policy.json", "owner-decision.json" }), "EXACT_INPUT_MEMBERS");
        return result;
    }

    private static bool Same(Dictionary<string, string> a, Dictionary<string, string> b) =>
        a.Count == b.Count && a.All(entry => b.TryGetValue(entry.Key, out string? value) && value == entry.Value);
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static void Axis(JsonElement report, string name, string status, string basis, string reason)
    {
        var axis = report.GetProperty(name);
        Equal(axis, "status", status);
        Equal(axis, "basis", basis);
        Equal(axis, "reason", reason);
    }
    private static void Equal(JsonElement value, string name, string expected) =>
        Require(value.GetProperty(name).GetString() == expected, "LITERAL_" + name);
    private static void Require(bool condition, string reason)
    {
        if (!condition)
            throw new InvalidOperationException("INDEPENDENT_ORACLE_" + reason);
    }
}
