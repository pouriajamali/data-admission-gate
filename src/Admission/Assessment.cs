using System.Text;
using System.Text.Json;
using MarketDataIntegrity;

namespace DataAdmission;

internal sealed record Axis(string Status, string Basis, string Reason);
internal sealed record Coverage(int Expected, int Accepted, int ExcludedQuarantined, int Missing, int Unexpected, int Duplicates, int NonAscending, string[] DiagnosticCodes, string Scope = "DECLARED_GRID_ONLY", string ExternalCompleteness = "NOT_PROVEN");
internal sealed record Freshness(string AsOf, string? LatestAccepted, long? AgeSeconds, int ThresholdSeconds, string ClockAccuracy = "NOT_PROVEN", string ActualSourceFreshness = "NOT_PROVEN");
internal sealed record Artifact(string File, int Bytes, string Sha256);
internal sealed record Assessment(string Schema, string Version, string ToolBuild, bool Complete, string Outcome, int ExitCode, string Profile, string Purpose, string DataSha256, string PolicySha256, string? DecisionSha256, bool OwnerDecisionAcknowledged, bool? DecisionBindingMatches, Axis RowQuality, Axis Coverage, Axis Freshness, Axis Provenance, Axis UseLicense, Coverage CoverageDetails, Freshness FreshnessDetails, Artifact[] PrivateArtifacts, string VendorRevision, string CsvSourceProvenance = "UNVERIFIED", string Identity = "NOT_PROVEN", string Authenticity = "NOT_PROVEN", string LegalRights = "NOT_PROVEN", string OriginalSoftwareLicense = "MIT", string Scope = "Offline policy decision only; owner assertions are not verified facts or legal permission proof. No trading/account/service action.");

internal static class Engine
{
    internal static Action<string, string>? BeforeFinalizeForTests = null;
    public static Assessment Run(string bundlePath, string destination, bool acknowledge)
    {
        bundlePath = Safe.Normalize(bundlePath); destination = Safe.Normalize(destination); Safe.Separate(destination, bundlePath); VendorPins.Check();
        var input = Bundle.Capture(bundlePath); var policy = Policy.Parse(input.Files["policy.json"]);
        OwnerDecision? decision = input.Files.TryGetValue("owner-decision.json", out var decisionBytes) ? OwnerDecision.Parse(decisionBytes) : null;
        bool? binding = decision == null ? null : decision.DatasetSha256 == input.Hash("input.csv") && decision.PolicySha256 == input.Hash("policy.json") && decision.Purpose == Contract.Purpose;
        string nonce = Guid.NewGuid().ToString("N"); Safe.Fresh(destination, nonce); string csvRoot = Path.Combine(destination, "csv-private"); Safe.NoLinks(csvRoot);
        CsvSummary summary;
        try
        {
            using var source = new MemoryStream(input.Files["input.csv"], false);
            summary = CsvValidator.Run(source, csvRoot, new CsvPolicy("ohlc-csv-v1", 2, 0, 4096, Contract.InputLimit, 1000, "USER_SUPPLIED_UNVERIFIED"));
        }
        catch (CsvFatalException e) { throw new Problem(e.Code); }
        if (summary.Status != "completed" || summary.InputSha256 != input.Hash("input.csv") || summary.InputBytes != input.Files["input.csv"].Length || summary.Records is < 1 or > 1000 || summary.Accepted + summary.Quarantined != summary.Records) throw new Problem("CSV_RESULT_BINDING_INVALID");
        var artifacts = ReadArtifacts(csvRoot); var accepted = ParseRows(artifacts.Bytes["accepted.jsonl"], true); var quarantined = ParseRows(artifacts.Bytes["quarantine.jsonl"], false);
        if (accepted.Count != summary.Accepted || quarantined.Count != summary.Quarantined) throw new Problem("CSV_RESULT_COUNT_INVALID");
        // Quarantined records can contain a nonnull CsvBar. They are never used
        // for grid/freshness, even when their timestamp looks valid.
        HashSet<string> expected = policy.ExpectedTimestamps.ToHashSet(StringComparer.Ordinal), seen = new(StringComparer.Ordinal); int missing, unexpected = 0, duplicates = 0, order = 0; string? previous = null; List<string> examples = [];
        void Example(string code) { if (examples.Count < 20) examples.Add(code); }
        foreach (string stamp in accepted)
        {
            if (!seen.Add(stamp)) { duplicates++; Example("DUPLICATE_ACCEPTED_TIMESTAMP"); }
            if (!expected.Contains(stamp)) { unexpected++; Example("UNEXPECTED_ACCEPTED_TIMESTAMP"); }
            if (previous != null && StringComparer.Ordinal.Compare(previous, stamp) >= 0) { order++; Example("NONASCENDING_ACCEPTED_TIMESTAMP"); } previous = stamp;
        }
        missing = expected.Count(t => !seen.Contains(t)); for (int i = 0; i < Math.Min(missing, 20); i++) Example("MISSING_DECLARED_SLOT");
        bool coveragePass = missing + unexpected + duplicates + order == 0;
        string? latest = accepted.Count == 0 ? null : accepted.Max(StringComparer.Ordinal); long? age = latest == null ? null : (Contract.Time(policy.AsOf).Ticks - Contract.Time(latest).Ticks) / TimeSpan.TicksPerSecond;
        var freshness = latest == null ? new Axis("UNKNOWN", "DECLARED_ASOF_ONLY", "NO_ACCEPTED_TIMESTAMP") : age < 0 ? new Axis("FAIL", "DECLARED_ASOF_ONLY", "FUTURE_ACCEPTED_TIMESTAMP") : age > policy.MaxAgeSeconds ? new Axis("FAIL", "DECLARED_ASOF_ONLY", "ACCEPTED_DATA_TOO_OLD") : new Axis("PASS", "DECLARED_ASOF_ONLY", "AGE_WITHIN_DECLARED_THRESHOLD");
        Axis DecisionAxis(string? value)
        {
            if (decision == null) return new("UNKNOWN", "NO_OWNER_DECISION", "DECISION_ABSENT");
            if (binding != true) return new("UNKNOWN", "INVALID_OWNER_DECISION_BINDING", "DECISION_BINDING_MISMATCH");
            if (!acknowledge) return new("UNKNOWN", "UNACKNOWLEDGED_OWNER_ASSERTION", "EXPLICIT_ACK_REQUIRED");
            return value switch { "allow" => new("PASS", "OWNER_DECISION_ACCEPTED", "OWNER_ASSERTION_ALLOW"), "deny" => new("FAIL", "OWNER_DECISION_ACCEPTED", "OWNER_ASSERTION_DENY"), _ => new("UNKNOWN", "OWNER_DECISION_ACCEPTED", "OWNER_ASSERTION_UNKNOWN") };
        }
        var rowQuality = new Axis(summary.Quarantined == 0 ? "PASS" : "FAIL", "PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY", summary.Quarantined == 0 ? "NO_QUARANTINED_ROWS" : "QUARANTINED_ROWS_PRESENT");
        var coverage = new Axis(coveragePass ? "PASS" : "FAIL", "DECLARED_GRID_ONLY", coveragePass ? "EXACT_ACCEPTED_GRID_AGREEMENT" : "ACCEPTED_GRID_MISMATCH");
        var provenance = DecisionAxis(decision?.Provenance); var license = DecisionAxis(decision?.UseLicense); Axis[] axes = [rowQuality, coverage, freshness, provenance, license];
        string outcome = binding == false || axes.Any(a => a.Status == "FAIL") ? "REJECT" : axes.Any(a => a.Status == "UNKNOWN") ? "HOLD" : "ADMIT"; int exit = outcome == "ADMIT" ? 0 : 2;
        var report = new Assessment("data-admission-report-v1", Contract.Version, Contract.Build, true, outcome, exit, Contract.Profile, Contract.Purpose, input.Hash("input.csv"), input.Hash("policy.json"), decisionBytes == null ? null : Contract.Hash(decisionBytes), acknowledge, binding, rowQuality, coverage, freshness, provenance, license,
            new(policy.ExpectedTimestamps.Length, accepted.Count, quarantined.Count, missing, unexpected, duplicates, order, examples.ToArray()), new(policy.AsOf, latest, age, policy.MaxAgeSeconds), artifacts.Inventory, Contract.VendorRevision);
        BeforeFinalizeForTests?.Invoke(bundlePath, destination);
        Safe.Owned(destination, nonce); var afterArtifacts = ReadArtifacts(csvRoot);
        if (!artifacts.Inventory.SequenceEqual(afterArtifacts.Inventory)) throw new Problem("CSV_ARTIFACT_CHANGED");
        byte[] json = Encoding.UTF8.GetBytes(Contract.Serialize(report) + "\n"), text = Encoding.UTF8.GetBytes($"Data Admission Gate: {outcome}\nProfile {Contract.Profile}; purpose {Contract.Purpose}\nRow quality {rowQuality.Status}; coverage {coverage.Status}; freshness {freshness.Status}; provenance {provenance.Status}; useLicense {license.Status}\nCoverage DECLARED_GRID_ONLY; freshness DECLARED_ASOF_ONLY.\nOwner basis is an assertion, not verified identity/authenticity/legal rights.\nIdentity/authenticity/legal rights/external completeness NOT_PROVEN.\nCSV row artifacts may contain input values; keep them private.\nOriginal reusable software MIT; upstream notices retained.\n");
        if (json.Length > Contract.JsonOutputLimit || text.Length > Contract.TextOutputLimit) throw new Problem("REPORT_BYTE_LIMIT");
        Safe.WriteNew(Path.Combine(destination, "summary.txt.pending"), text); Safe.WriteNew(Path.Combine(destination, "summary.json.pending"), json);
        input.Recheck(); Safe.Owned(destination, nonce);
        File.Move(Path.Combine(destination, "summary.txt.pending"), Path.Combine(destination, "summary.txt"));
        File.Move(Path.Combine(destination, "summary.json.pending"), Path.Combine(destination, "summary.json")); return report;
    }
    internal static (Dictionary<string, byte[]> Bytes, Artifact[] Inventory) ReadArtifacts(string folder)
    {
        Safe.NoLinks(folder);
        Dictionary<string, int> allowed = new(StringComparer.Ordinal) { ["run.lock"] = 0, ["accepted.jsonl"] = 1024 * 1024, ["quarantine.jsonl"] = 1024 * 1024, ["summary.json"] = 65536 };
        Dictionary<string, byte[]> bytes = new(StringComparer.Ordinal); List<Artifact> inventory = []; int total = 0;
        foreach (string path in Directory.EnumerateFileSystemEntries(folder))
        {
            string name = Path.GetFileName(path); if (bytes.Count == 4 || !allowed.TryGetValue(name, out int cap)) throw new Problem("CSV_ARTIFACT_INVENTORY_INVALID");
            byte[] b = Safe.Read(path, cap); total = checked(total + b.Length); if (total > Contract.ArtifactLimit) throw new Problem("CSV_ARTIFACT_BYTE_LIMIT"); bytes.Add(name, b); inventory.Add(new(name, b.Length, Contract.Hash(b)));
        }
        if (bytes.Count != 4 || !bytes.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(allowed.Keys)) throw new Problem("CSV_ARTIFACT_INVENTORY_INVALID");
        return (bytes, inventory.OrderBy(a => a.File, StringComparer.Ordinal).ToArray());
    }
    private static List<string> ParseRows(byte[] bytes, bool accepted)
    {
        List<string> timestamps = []; if (bytes.Length == 0) return timestamps;
        string text = new UTF8Encoding(false, true).GetString(bytes); if (!text.EndsWith('\n')) throw new Problem("CSV_ARTIFACT_FORMAT_INVALID");
        string[] rows = text.Split('\n'); if (rows.Length > 1001) throw new Problem("CSV_ARTIFACT_ROW_LIMIT");
        foreach (string row in rows[..^1])
        {
            if (Encoding.UTF8.GetByteCount(row) + 1 > 1024) throw new Problem("CSV_ARTIFACT_LINE_LIMIT"); using var d = Contract.Document(Encoding.UTF8.GetBytes(row), 1024); var r = d.RootElement;
            Contract.Fields(r, "line", "offset", "byteLength", "rawSha256", "reason", "field", "record");
            if (Contract.Integer(r, "line") is < 2 or > 1001 || Contract.Integer(r, "offset") > Contract.InputLimit || Contract.Integer(r, "byteLength") > 4096) throw new Problem("CSV_ARTIFACT_METADATA_INVALID"); Contract.Sha(Contract.Text(r, "rawSha256"));
            if ((Contract.Text(r, "reason") == "VALID_ROW") != accepted) throw new Problem("CSV_ARTIFACT_CLASS_INVALID");
            if (accepted)
            {
                var record = r.GetProperty("record"); Contract.Fields(record, "timestamp", "openScaled", "highScaled", "lowScaled", "closeScaled", "volumeScaled"); string stamp = Contract.Text(record, "timestamp"); Contract.Time(stamp); timestamps.Add(stamp);
            }
            else timestamps.Add(""); // Count only; never inspect a quarantined record timestamp.
        }
        return timestamps;
    }
}
