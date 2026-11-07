using System.Text;
using System.Text.Json;
using DataAdmission;
using App = DataAdmission.Program;

internal static class Program
{
    private static string Root = ""; private static int Passed, Failed, Skipped; private static readonly List<object> Results = [];
    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);
    private static string PathFor(string name) => Path.Combine(Root, name);
    private static void Assert(bool c, string reason = "ASSERTION") { if (!c) throw new Exception(reason); }
    private static void Problem(Action action, string? reason = null)
    {
        try { action(); } catch (DataAdmission.Problem p) { Assert(reason == null || p.Code == reason, "WRONG_REASON_" + p.Code); return; } throw new Exception("EXPECTED_PROBLEM");
    }
    private static void Test(string name, Action action)
    {
        try { action(); Passed++; Results.Add(new { name, outcome = "pass" }); Console.WriteLine("PASS " + name); }
        catch (Exception e) { Failed++; Results.Add(new { name, outcome = "fail", reason = e.GetType().Name, detail = e.Message }); Console.WriteLine("FAIL " + name + " " + e.GetType().Name + " " + e.Message); }
        finally { Engine.BeforeFinalizeForTests = null; }
    }
    private static (int Exit, JsonElement Json) Cli(params string[] args)
    {
        var original = Console.Out; using var text = new StringWriter(); int exit; try { Console.SetOut(text); exit = App.Main(args); } finally { Console.SetOut(original); }
        using var d = JsonDocument.Parse(text.ToString()); return (exit, d.RootElement.Clone());
    }
    private static string NewBundle(string name, string? csv = null, byte[]? policy = null) => Fixtures.Bundle(PathFor(name + "-bundle"), csv, policy);
    private static Assessment Assess(string name, string? csv = null, byte[]? policy = null, Action<string>? decision = null, bool ack = false)
    { string b = NewBundle(name, csv, policy); decision?.Invoke(b); return Engine.Run(b, PathFor(name + "-report"), ack); }
    private static void NoReport(string name) => Assert(!File.Exists(Path.Combine(PathFor(name), "summary.json")), "UNEXPECTED_FINAL_REPORT");
    public static int Main(string[] args)
    {
        if (args is not ["--work", var work]) return 90; Root = Safe.Normalize(work); Safe.Fresh(Root, Guid.NewGuid().ToString("N"));
        PolicyAndDecisions(); Mechanical(); SnapshotsAndBounds(); PathsAndSurface();
        var receipt = new { schema = "admission-tests-v1", passed = Passed, failed = Failed, skipped = Skipped, cases = Results, limits = "Synthetic local fixtures only; no actual ownership/rights/market/freshness proof; original software license pending." };
        Safe.WriteNew(PathFor("receipt.json"), Bytes(Contract.Serialize(receipt) + "\n")); Console.WriteLine($"SUMMARY passed={Passed} failed={Failed} skipped={Skipped}"); return Failed == 0 ? 0 : 1;
    }
    private static void PolicyAndDecisions()
    {
        byte[] valid = Fixtures.PolicyBytes(); string json = Encoding.UTF8.GetString(valid);
        foreach (string field in new[] { "schema", "profile", "purpose", "asOf", "maxAgeSeconds", "expectedTimestamps" })
            Test("policy-missing-" + field, () => { using var d = JsonDocument.Parse(valid); var map = d.RootElement.EnumerateObject().Where(p => p.Name != field).ToDictionary(p => p.Name, p => p.Value.Clone()); Problem(() => Policy.Parse(Bytes(Contract.Serialize(map))), "JSON_FIELDS_INVALID"); });
        foreach (var token in new[] { ("fraction", "1.0"), ("exponent", "1e0"), ("negative", "-1"), ("string", "\"1\""), ("overflow", "9223372036854775808") })
            Test("policy-integer-" + token.Item1, () => Problem(() => Policy.Parse(Bytes(json.Replace("\"maxAgeSeconds\":60", "\"maxAgeSeconds\":" + token.Item2, StringComparison.Ordinal))), "INTEGER_ENCODING_INVALID"));
        Test("policy-age-max-and-over", () => { Assert(Policy.Parse(Fixtures.PolicyBytes(age: 604800)).MaxAgeSeconds == 604800); Problem(() => Policy.Parse(Fixtures.PolicyBytes(age: 604801)), "AGE_LIMIT_INVALID"); });
        Test("policy-duplicate-key", () => Problem(() => Policy.Parse(Bytes(json.TrimStart().Insert(1, "\"maxAgeSeconds\":60,"))), "JSON_DUPLICATE_KEY"));
        Test("policy-unknown-field", () => Problem(() => Policy.Parse(Bytes(json.TrimStart().Insert(1, "\"unknown\":1,"))), "JSON_FIELDS_INVALID"));
        Test("policy-profile-purpose", () => { Problem(() => Policy.Parse(Bytes(json.Replace(Contract.Profile, "future", StringComparison.Ordinal))), "POLICY_PROFILE_UNSUPPORTED"); Problem(() => Policy.Parse(Bytes(json.Replace(Contract.Purpose, "trading", StringComparison.Ordinal))), "POLICY_PROFILE_UNSUPPORTED"); });
        Test("policy-empty-grid", () => Problem(() => Policy.Parse(Fixtures.PolicyBytes(grid: [])), "GRID_COUNT_INVALID"));
        Test("policy-duplicate-or-descending-grid", () => { Problem(() => Policy.Parse(Fixtures.PolicyBytes(grid: [Fixtures.Grid[0], Fixtures.Grid[0]])), "GRID_ORDER_OR_DUPLICATE_INVALID"); Problem(() => Policy.Parse(Fixtures.PolicyBytes(grid: Fixtures.Grid.Reverse().ToArray())), "GRID_ORDER_OR_DUPLICATE_INVALID"); });
        Test("policy-grid-1001-cap", () => Problem(() => Policy.Parse(Fixtures.PolicyBytes(grid: Enumerable.Range(0, 1001).Select(i => DateTimeOffset.Parse("2026-01-01T00:00:00Z").AddSeconds(i).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")).ToArray())), "GRID_COUNT_INVALID"));
        foreach (string stamp in new[] { "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00z", "2026-01-01T00:00:00.0Z", "2026-02-29T00:00:00Z", "2026-01-01T00:00:60Z", "2026-01-01T00:00:00Z\n" })
            Test("timestamp-reject-" + stamp.Replace(':', '_').Replace('\n', '_'), () => Problem(() => Contract.Time(stamp), "UTC_TIMESTAMP_INVALID"));
        Test("policy-depth-cap", () => Problem(() => Policy.Parse(Bytes(new string('[', 9) + new string(']', 9))), "JSON_INVALID"));
        Test("policy-bom-trailing-bytes", () => { Problem(() => Policy.Parse([0xef, 0xbb, 0xbf, .. valid]), "JSON_INVALID"); Problem(() => Policy.Parse([.. valid, .. Bytes("{}")]), "JSON_INVALID"); });
        Test("policy-actual-byte-cap", () => Problem(() => Policy.Parse(new byte[Contract.PolicyLimit + 1]), "JSON_BYTE_LIMIT"));
        Test("labels-hashes-all-controls-and-anchors", () =>
        {
            foreach (char c in Enumerable.Range(0, 160).Select(i => (char)i).Where(char.IsControl).Concat(new[] { '\u2028', '\u2029', '\ufeff' }))
                foreach (string label in new[] { c + "OWNER", "OWN" + c + "ER", "OWNER" + c }) Problem(() => Contract.Label(label), "LABEL_INVALID");
            Problem(() => Contract.Sha(new string('a', 64) + "\n")); Problem(() => Contract.Sha(new string('A', 64))); Problem(() => Contract.Label(new string('a', 65))); Assert(Contract.Label(new string('a', 64)).Length == 64);
        });
        Test("decision-absent-default-hold", () => { var r = Assess("absent"); Assert(r.Outcome == "HOLD" && r.ExitCode == 2 && r.Provenance.Status == "UNKNOWN" && r.UseLicense.Status == "UNKNOWN" && r.DecisionBindingMatches == null); });
        Test("decision-present-without-ack-hold", () => { var r = Assess("unack", decision: b => Fixtures.Decision(b)); Assert(r.Outcome == "HOLD" && r.DecisionBindingMatches == true && r.Provenance.Basis == "UNACKNOWLEDGED_OWNER_ASSERTION"); });
        Test("decision-explicit-ack-is-assertion-not-proof", () => { var r = Assess("ack", decision: b => Fixtures.Decision(b), ack: true); Assert(r.Outcome == "ADMIT" && r.Provenance.Basis == "OWNER_DECISION_ACCEPTED" && r.UseLicense.Basis == "OWNER_DECISION_ACCEPTED" && r.Identity == "NOT_PROVEN" && r.Authenticity == "NOT_PROVEN" && r.LegalRights == "NOT_PROVEN" && r.CsvSourceProvenance == "UNVERIFIED"); });
        Test("ack-absent-decision-stays-hold", () => Assert(Assess("ack-missing", ack: true).Outcome == "HOLD"));
        foreach (string axis in new[] { "provenance", "license" })
            Test("decision-independent-denial-" + axis, () => { var r = Assess("deny-" + axis, decision: b => Fixtures.Decision(b, provenance: axis == "provenance" ? "deny" : "allow", license: axis == "license" ? "deny" : "allow"), ack: true); Assert(r.Outcome == "REJECT" && (axis == "provenance" ? r.Provenance.Status == "FAIL" && r.UseLicense.Status == "PASS" : r.UseLicense.Status == "FAIL" && r.Provenance.Status == "PASS")); });
        Test("decision-explicit-unknown", () => Assert(Assess("unknown", decision: b => Fixtures.Decision(b, license: "unknown"), ack: true).Outcome == "HOLD"));
        foreach (bool ack in new[] { false, true })
            foreach (string field in new[] { "dataset", "policy", "purpose" })
                Test("decision-binding-" + field + "-ack-" + ack, () => { var r = Assess("binding-" + field + ack, decision: b => Fixtures.Decision(b, datasetHash: field == "dataset" ? new string('0', 64) : null, policyHash: field == "policy" ? new string('0', 64) : null, purpose: field == "purpose" ? "different" : null), ack: ack); Assert(r.Outcome == "REJECT" && r.DecisionBindingMatches == false && r.Provenance.Status == "UNKNOWN"); });
        Test("decision-malformed-even-without-ack", () => { string b = NewBundle("bad-decision"); File.WriteAllText(Path.Combine(b, "owner-decision.json"), "{}"); var r = Cli("assess", b, PathFor("bad-decision-report")); Assert(r.Exit == 1 && !r.Json.GetProperty("complete").GetBoolean()); NoReport("bad-decision-report"); });
        string decisionBundle = NewBundle("decision-shape"); Fixtures.Decision(decisionBundle); byte[] good = File.ReadAllBytes(Path.Combine(decisionBundle, "owner-decision.json")); string goodText = Encoding.UTF8.GetString(good);
        foreach (string field in new[] { "schema", "datasetSha256", "policySha256", "purpose", "ownerLabel", "evidenceRefs", "provenance", "useLicense" })
            Test("decision-missing-" + field, () => { using var d = JsonDocument.Parse(good); var map = d.RootElement.EnumerateObject().Where(p => p.Name != field).ToDictionary(p => p.Name, p => p.Value.Clone()); Problem(() => OwnerDecision.Parse(Bytes(Contract.Serialize(map))), "JSON_FIELDS_INVALID"); });
        Test("decision-duplicate-key", () => Problem(() => OwnerDecision.Parse(Bytes(goodText.Insert(1, "\"provenance\":\"allow\","))), "JSON_DUPLICATE_KEY"));
        Test("decision-unsupported-value", () => Problem(() => OwnerDecision.Parse(Bytes(goodText.Replace("\"provenance\":\"allow\"", "\"provenance\":\"verified\"", StringComparison.Ordinal))), "DECISION_VALUE_INVALID"));
        Test("decision-byte-cap", () => Problem(() => OwnerDecision.Parse(new byte[Contract.DecisionLimit + 1]), "JSON_BYTE_LIMIT"));
    }
    private static void Mechanical()
    {
        Test("coverage-exact-grid-is-not-external-completeness", () => { var r = Assess("grid"); Assert(r.Coverage.Status == "PASS" && r.CoverageDetails.Scope == "DECLARED_GRID_ONLY" && r.CoverageDetails.ExternalCompleteness == "NOT_PROVEN" && r.Freshness.Basis == "DECLARED_ASOF_ONLY" && r.FreshnessDetails.ActualSourceFreshness == "NOT_PROVEN"); });
        Test("coverage-missing-unexpected-duplicate-order-counts", () => { var r = Assess("counts", Fixtures.Csv([Fixtures.Grid[1], Fixtures.Grid[0], Fixtures.Grid[0], "2026-01-01T00:03:00Z"])); Assert(r.Outcome == "REJECT" && r.CoverageDetails.Missing == 1 && r.CoverageDetails.Unexpected == 1 && r.CoverageDetails.Duplicates == 1 && r.CoverageDetails.NonAscending == 2); });
        Test("coverage-examples-capped-totals-exact", () => { var r = Assess("many-duplicates", Fixtures.Csv(Enumerable.Repeat(Fixtures.Grid[0], 1000))); Assert(r.CoverageDetails.Duplicates == 999 && r.CoverageDetails.NonAscending == 999 && r.CoverageDetails.Missing == 2 && r.CoverageDetails.DiagnosticCodes.Length == 20); });
        Test("freshness-exact-threshold", () => { var r = Assess("fresh-boundary", policy: Fixtures.PolicyBytes("2026-01-01T00:03:00Z")); Assert(r.Freshness.Status == "PASS" && r.FreshnessDetails.AgeSeconds == 60); });
        Test("freshness-one-second-stale", () => { var r = Assess("stale-boundary", policy: Fixtures.PolicyBytes("2026-01-01T00:03:01Z")); Assert(r.Freshness.Status == "FAIL" && r.FreshnessDetails.AgeSeconds == 61); });
        Test("freshness-zero-age", () => Assert(Assess("zero-age", policy: Fixtures.PolicyBytes(age: 0)).Freshness.Status == "PASS"));
        Test("freshness-future-is-fail", () => { var r = Assess("future", policy: Fixtures.PolicyBytes("2026-01-01T00:01:59Z")); Assert(r.Freshness.Status == "FAIL" && r.Freshness.Reason == "FUTURE_ACCEPTED_TIMESTAMP" && r.Outcome == "REJECT"); });
        Test("owner-cannot-override-mechanical-failure", () => { var r = Assess("override", Fixtures.Csv([Fixtures.Grid[0]]), decision: b => Fixtures.Decision(b), ack: true); Assert(r.Outcome == "REJECT" && r.Provenance.Status == "PASS" && r.UseLicense.Status == "PASS" && r.Coverage.Status == "FAIL"); });
        Test("all-quarantined-nonnull-record-never-freshness", () =>
        {
            string csv = "timestamp,open,high,low,close,volume\n2026-01-01T00:02:00Z,100.00,90.00,110.00,100.00,5\n";
            var r = Assess("all-quarantined", csv, decision: b => Fixtures.Decision(b), ack: true); Assert(r.RowQuality.Status == "FAIL" && r.Outcome == "REJECT" && r.ExitCode == 2 && r.CoverageDetails.Accepted == 0 && r.CoverageDetails.ExcludedQuarantined == 1 && r.Freshness.Status == "UNKNOWN" && r.FreshnessDetails.LatestAccepted == null);
            Assert(File.ReadAllText(Path.Combine(PathFor("all-quarantined-report"), "csv-private/quarantine.jsonl")).Contains("\"record\":{", StringComparison.Ordinal));
        });
        Test("quarantine-outlier-cannot-fake-latest", () => { string csv = Fixtures.Csv([Fixtures.Grid[0]]) + "2026-01-01T00:02:00Z,100.00,90.00,110.00,100.00,5\n"; var r = Assess("quarantine-outlier", csv); Assert(r.FreshnessDetails.LatestAccepted == Fixtures.Grid[0] && r.Freshness.Status == "FAIL" && r.RowQuality.Status == "FAIL"); });
        foreach (var data in new[] { ("empty", ""), ("header-only", "timestamp,open,high,low,close,volume\n"), ("bad-header", "time,open,high,low,close,volume\n"), ("unclosed-quote", "timestamp,open,high,low,close,volume\n\"2026-01-01T00:00:00Z,1,2,0,1,1\n") })
            Test("vendor-file-fatal-" + data.Item1, () => { string b = NewBundle("fatal-" + data.Item1, data.Item2); string output = "fatal-report-" + data.Item1; var r = Cli("assess", b, PathFor(output)); Assert(r.Exit == 1 && r.Json.GetProperty("outcome").GetString() == "INCOMPLETE"); NoReport(output); });
        Test("vendor-no-silent-rounding", () => { var r = Assess("precision", Fixtures.Csv().Replace("100.00", "100.001", StringComparison.Ordinal)); Assert(r.RowQuality.Status == "FAIL" && r.CoverageDetails.Accepted == 0 && r.CoverageDetails.ExcludedQuarantined == 3); });
        Test("vendor-fixed-scales-keep-signed-values", () => { string csv = "timestamp,open,high,low,close,volume\n2026-01-01T00:00:00Z,-1.25,0.00,-2.00,-0.50,0\n"; var r = Assess("signed", csv, Fixtures.PolicyBytes(grid: [Fixtures.Grid[0]])); Assert(r.RowQuality.Status == "PASS" && r.Coverage.Status == "PASS"); Assert(File.ReadAllText(Path.Combine(PathFor("signed-report"), "csv-private/accepted.jsonl")).Contains("\"openScaled\":\"-125\"", StringComparison.Ordinal)); });
        Test("actual-1000-record-output-bounds", () =>
        {
            var start = DateTimeOffset.Parse("2026-01-01T00:00:00Z"); string[] grid = Enumerable.Range(0, 1000).Select(i => start.AddSeconds(i).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")).ToArray();
            string csv = "timestamp,open,high,low,close,volume\n" + string.Join("", grid.Select(t => t + ",-92233720368547758.08,92233720368547758.07,-92233720368547758.08,92233720368547758.07,9223372036854775807\n"));
            var r = Assess("maximum", csv, Fixtures.PolicyBytes(grid[^1], 0, grid), b => Fixtures.Decision(b), true); Assert(r.Outcome == "ADMIT" && r.CoverageDetails.Accepted == 1000 && r.PrivateArtifacts.Sum(a => a.Bytes) < Contract.ArtifactLimit);
            Assert(new FileInfo(Path.Combine(PathFor("maximum-report"), "summary.json")).Length <= Contract.JsonOutputLimit && new FileInfo(Path.Combine(PathFor("maximum-report"), "summary.txt")).Length <= Contract.TextOutputLimit);
        });
        Test("vendor-row-1001-cap-incomplete", () => { string b = NewBundle("row-cap", Fixtures.Csv(Enumerable.Repeat(Fixtures.Grid[0], 1001))); var r = Cli("assess", b, PathFor("row-cap-report")); Assert(r.Exit == 1 && r.Json.GetProperty("reason").GetString() == "CSV_ROW_LIMIT"); NoReport("row-cap-report"); });
    }
    private static void SnapshotsAndBounds()
    {
        foreach (string mutation in new[] { "add-decision", "remove-decision", "change-decision", "change-data", "change-policy", "add-member" })
            Test("late-snapshot-" + mutation, () =>
            {
                string b = NewBundle("late-" + mutation); if (mutation is "remove-decision" or "change-decision") Fixtures.Decision(b);
                Engine.BeforeFinalizeForTests = (bundle, _) =>
                {
                    switch (mutation)
                    {
                        case "add-decision": Fixtures.Decision(bundle); break;
                        case "remove-decision": File.Delete(Path.Combine(bundle, "owner-decision.json")); break;
                        case "change-decision": File.AppendAllText(Path.Combine(bundle, "owner-decision.json"), " "); break;
                        case "change-data": File.AppendAllText(Path.Combine(bundle, "input.csv"), " "); break;
                        case "change-policy": File.AppendAllText(Path.Combine(bundle, "policy.json"), " "); break;
                        default: File.WriteAllText(Path.Combine(bundle, "unexpected"), "x"); break;
                    }
                };
                string output = "late-report-" + mutation; var r = Cli("assess", b, PathFor(output), "--ack-owner-decision"); Assert(r.Exit == 1 && r.Json.GetProperty("reason").GetString() == "INPUT_CHANGED"); NoReport(output);
            });
        Test("hashes-bind-same-captured-bytes", () =>
        {
            string b = NewBundle("hashes"); Fixtures.Decision(b); var before = Bundle.Capture(b); var r = Engine.Run(b, PathFor("hashes-report"), true);
            Assert(r.DataSha256 == Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(before.Files["input.csv"])).ToLowerInvariant() && r.PolicySha256 == Contract.Hash(before.Files["policy.json"]) && r.DecisionSha256 == Contract.Hash(before.Files["owner-decision.json"])); before.Recheck();
        });
        Test("assessment-never-mutates-bundle", () => { string b = NewBundle("read-only"); Fixtures.Decision(b); var before = Bundle.Capture(b); Engine.Run(b, PathFor("read-only-report"), true); before.Recheck(); });
        Test("ack-is-not-persistent", () => { string b = NewBundle("per-invocation"); Fixtures.Decision(b); Assert(Engine.Run(b, PathFor("ack-on-report"), true).Outcome == "ADMIT"); Assert(Engine.Run(b, PathFor("ack-off-report"), false).Outcome == "HOLD"); });
        foreach (string artifact in new[] { "accepted.jsonl", "quarantine.jsonl", "summary.json" })
            Test("artifact-late-change-" + artifact, () => { string b = NewBundle("artifact-change-" + artifact); Engine.BeforeFinalizeForTests = (_, output) => File.AppendAllText(Path.Combine(output, "csv-private", artifact), " "); string result = "artifact-change-report-" + artifact; Assert(Cli("assess", b, PathFor(result)).Exit == 1); NoReport(result); });
        Test("artifact-oversize-refused-before-final", () => { string b = NewBundle("artifact-size"); Engine.BeforeFinalizeForTests = (_, o) => { using var f = File.OpenWrite(Path.Combine(o, "csv-private/accepted.jsonl")); f.SetLength(1024 * 1024 + 1); }; Assert(Cli("assess", b, PathFor("artifact-size-report")).Exit == 1); NoReport("artifact-size-report"); });
        Test("artifact-inventory-extra-refused", () => { string b = NewBundle("artifact-extra"); Engine.BeforeFinalizeForTests = (_, o) => File.WriteAllText(Path.Combine(o, "csv-private/extra"), "x"); Assert(Cli("assess", b, PathFor("artifact-extra-report")).Exit == 1); NoReport("artifact-extra-report"); });
        Test("report-write-collision-incomplete", () => { string b = NewBundle("collision"); Engine.BeforeFinalizeForTests = (_, o) => File.WriteAllText(Path.Combine(o, "summary.json.pending"), "occupied"); Assert(Cli("assess", b, PathFor("collision-report")).Exit == 1); NoReport("collision-report"); });
        Test("report-marker-change-incomplete", () => { string b = NewBundle("marker"); Engine.BeforeFinalizeForTests = (_, o) => File.WriteAllText(Path.Combine(o, ".admission-owned"), new string('0', 32)); Assert(Cli("assess", b, PathFor("marker-report")).Exit == 1); NoReport("marker-report"); });
        foreach (var cap in new[] { ("input.csv", Contract.InputLimit), ("policy.json", Contract.PolicyLimit), ("owner-decision.json", Contract.DecisionLimit) })
            Test("bundle-actual-byte-cap-" + cap.Item1, () => { string b = NewBundle("cap-" + cap.Item1); using (var f = File.OpenWrite(Path.Combine(b, cap.Item1))) f.SetLength(cap.Item2 + 1); Problem(() => Bundle.Capture(b), "INPUT_BYTE_LIMIT"); });
        Test("vendor-source-byte-pins", () =>
        {
            VendorPins.Check(); string target = PathFor("vendor-copy"); Directory.CreateDirectory(target); foreach (string f in Directory.EnumerateFiles(Path.Combine(AppContext.BaseDirectory, "vendor/integrity-csv"))) File.Copy(f, Path.Combine(target, Path.GetFileName(f)));
            File.AppendAllText(Path.Combine(target, "CsvValidator.cs"), " "); Problem(() => VendorPins.Check(target), "VENDOR_PIN_INVALID");
        });
        Test("no-owner-label-or-raw-private-data-in-main-report", () =>
        {
            string b = NewBundle("private-label"); Fixtures.Decision(b); string p = Path.Combine(b, "owner-decision.json"); File.WriteAllText(p, File.ReadAllText(p).Replace("SYNTHETIC_DEMO_OWNER", "PRIVATE_OWNER_SECRET", StringComparison.Ordinal));
            var r = Engine.Run(b, PathFor("private-label-report"), true); string main = File.ReadAllText(Path.Combine(PathFor("private-label-report"), "summary.json")); Assert(r.Outcome == "ADMIT" && !main.Contains("PRIVATE_OWNER_SECRET", StringComparison.Ordinal) && !main.Contains("100.00", StringComparison.Ordinal) && !main.Contains(Root, StringComparison.Ordinal));
        });
    }
    private static void PathsAndSurface()
    {
        Test("bundle-unknown-and-case-mismatch", () => { string b = NewBundle("member"); File.WriteAllText(Path.Combine(b, "OWNER-DECISION.JSON"), "{}"); Problem(() => Bundle.Capture(b), "BUNDLE_MEMBER_UNSUPPORTED"); });
        Test("bundle-directory-refused", () => { string b = NewBundle("directory"); Directory.CreateDirectory(Path.Combine(b, "owner-decision.json")); Problem(() => Bundle.Capture(b), "REGULAR_FILE_REQUIRED"); });
        Test("bundle-missing-required", () => { string b = PathFor("missing-member"); Directory.CreateDirectory(b); File.WriteAllText(Path.Combine(b, "input.csv"), Fixtures.Csv()); Problem(() => Bundle.Capture(b), "BUNDLE_REQUIRED_MEMBER_MISSING"); });
        Test("path-all-control-positions", () => { foreach (char c in Enumerable.Range(0, 160).Select(i => (char)i).Where(char.IsControl).Concat(new[] { '\u2028', '\u2029', '\ufeff' })) foreach (string p in new[] { c + "demo", "de" + c + "mo", "demo" + c }) Problem(() => Safe.Normalize(p), "PATH_UNSUPPORTED"); });
        Test("path-network-and-length", () => { Problem(() => Safe.Normalize(@"\\host\share")); Problem(() => Safe.Normalize("//host/share")); Problem(() => Safe.Normalize(PathFor(new string('x', 400)))); });
        Test("path-output-ancestor-descendant-sibling", () => { string b = NewBundle("overlap"); Problem(() => Engine.Run(b, Path.Combine(b, "output"), false), "OUTPUT_OVERLAPS_INPUT"); Problem(() => Safe.Separate(b, Path.GetPathRoot(b)!), "OUTPUT_OVERLAPS_INPUT"); Safe.Separate(b + "-sibling", b); });
        Test("output-existing-is-preserved", () => { string b = NewBundle("existing"); string output = PathFor("existing-output"); Directory.CreateDirectory(output); File.WriteAllText(Path.Combine(output, "sentinel"), "unchanged"); Assert(Cli("assess", b, output).Exit == 1 && File.ReadAllText(Path.Combine(output, "sentinel")) == "unchanged"); });
        Test("cli-invalid-ack-and-no-live-options", () => { foreach (string flag in new[] { "--host", "--trade", "--url", "--sql", "--plugin", "--config", "--force-admit", "--verify-rights" }) Assert(Cli(flag).Exit == 1); string b = NewBundle("extra-ack"); Assert(Cli("assess", b, PathFor("extra-ack-report"), "--ack-owner-decision", "--ack-owner-decision").Exit == 1); });
        Test("cli-error-safe-versioned-metadata", () => { var r = Cli("assess", PathFor("PRIVATE_MISSING_INPUT"), PathFor("PRIVATE_OUTPUT")); string json = r.Json.ToString(); Assert(r.Exit == 1 && !r.Json.GetProperty("complete").GetBoolean() && r.Json.GetProperty("schema").GetString() == "data-admission-error-v1" && r.Json.GetProperty("version").GetString() == Contract.Version && !json.Contains("PRIVATE_", StringComparison.Ordinal) && r.Json.GetProperty("legalRights").GetString() == "NOT_PROVEN"); });
        Test("demo-five-expected-outcomes", () => { var r = Cli("demo", PathFor("demo with spaces")); Assert(r.Exit == 0 && r.Json.GetProperty("cases").GetArrayLength() == 5 && r.Json.GetProperty("outcome").GetString() == "EXPECTED_OUTCOMES_OBSERVED"); });
        try
        {
            string target = PathFor("symlink-target"); File.WriteAllText(target, "{}"); string link = PathFor("symlink-input"); File.CreateSymbolicLink(link, target); Test("symlink-refused", () => Problem(() => Safe.Read(link, 16), "LINK_UNSUPPORTED"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Skipped++; Results.Add(new { name = "symlink-refused", outcome = "skip", reason = "LOCAL_SYMLINK_PRIVILEGE" }); }
        if (OperatingSystem.IsLinux()) Test("linux-fifo-refused-before-open", () =>
        {
            string p = PathFor("fifo-input"); using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("mkfifo") { UseShellExecute = false, ArgumentList = { p } })!; Assert(child.WaitForExit(3000) && child.ExitCode == 0); Problem(() => Safe.Read(p, 16), "REGULAR_FILE_REQUIRED");
        });
        else { Skipped++; Results.Add(new { name = "linux-fifo-refused-before-open", outcome = "skip", reason = "LINUX_ONLY" }); }
    }
}
