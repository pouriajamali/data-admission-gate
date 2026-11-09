using System.Text;

namespace DataAdmission;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args is ["--version"]) { Console.WriteLine("Data Admission Gate " + Contract.Version + ""); return 0; }
            object result; int exit;
            switch (args)
            {
                case ["assess", var bundle, var output]: var report = Engine.Run(bundle, output, false); result = report; exit = report.ExitCode; break;
                case ["assess", var bundle, var output, "--ack-owner-decision"]: var acknowledged = Engine.Run(bundle, output, true); result = acknowledged; exit = acknowledged.ExitCode; break;
                case ["demo", var output]: result = Demo.Run(output); exit = 0; break;
                default: throw new Problem("CLI_INVALID");
            }
            Console.WriteLine(Contract.Serialize(result)); return exit;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Console.WriteLine(Contract.Serialize(new { schema = "data-admission-error-v1", version = Contract.Version, toolBuild = Contract.Build, complete = false, outcome = "INCOMPLETE", exitCode = 1, reason = e is Problem p ? p.Code : "IO_OR_CONFIGURATION_FAILURE", identity = "NOT_PROVEN", authenticity = "NOT_PROVEN", legalRights = "NOT_PROVEN", originalSoftwareLicense = "MIT" })); return 1;
        }
    }
}

internal static class Fixtures
{
    public static readonly string[] Grid = ["2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z"];
    public static string Csv(IEnumerable<string>? stamps = null) => "timestamp,open,high,low,close,volume\n" + string.Join("", (stamps ?? Grid).Select(t => t + ",100.00,102.00,99.00,101.00,5\n"));
    public static byte[] PolicyBytes(string? asOf = null, int age = 60, string[]? grid = null) => Encoding.UTF8.GetBytes(Contract.Serialize(new { schema = "data-admission-policy-v1", profile = Contract.Profile, purpose = Contract.Purpose, asOf = asOf ?? Grid[^1], maxAgeSeconds = age, expectedTimestamps = grid ?? Grid }) + "\n");
    public static string Bundle(string directory, string? csv = null, byte[]? policy = null)
    {
        directory = Safe.Normalize(directory); Safe.NoLinks(directory); if (Directory.Exists(directory) || File.Exists(directory)) throw new Problem("OUTPUT_EXISTS"); Directory.CreateDirectory(directory);
        Safe.WriteNew(Path.Combine(directory, "input.csv"), Encoding.UTF8.GetBytes(csv ?? Csv())); Safe.WriteNew(Path.Combine(directory, "policy.json"), policy ?? PolicyBytes()); return directory;
    }
    public static void Decision(string bundle, string provenance = "allow", string license = "allow", string? datasetHash = null, string? policyHash = null, string? purpose = null)
    {
        var captured = DataAdmission.Bundle.Capture(bundle);
        var value = new { schema = "owner-decision-v1", datasetSha256 = datasetHash ?? captured.Hash("input.csv"), policySha256 = policyHash ?? captured.Hash("policy.json"), purpose = purpose ?? Contract.Purpose, ownerLabel = "SYNTHETIC_DEMO_OWNER", evidenceRefs = new[] { "GENERATED_EXAMPLE_NOT_A_REAL_RIGHTS_GRANT" }, provenance, useLicense = license };
        Safe.WriteNew(Path.Combine(bundle, "owner-decision.json"), Encoding.UTF8.GetBytes(Contract.Serialize(value) + "\n"));
    }
}
internal static class Demo
{
    public static object Run(string destination)
    {
        destination = Safe.Normalize(destination); string nonce = Guid.NewGuid().ToString("N"); VendorPins.Check(); Safe.Fresh(destination, nonce);
        List<object> cases = []; List<Assessment> reports = [];
        void Case(string name, string expected, bool ack, Action<string>? prepare = null)
        {
            string bundle = Fixtures.Bundle(Path.Combine(destination, name + "-bundle")); prepare?.Invoke(bundle); var r = Engine.Run(bundle, Path.Combine(destination, name + "-report"), ack);
            if (!r.Complete || r.Outcome != expected) throw new Problem("DEMO_ASSERTION_FAILED"); reports.Add(r); cases.Add(new { name, expected, actual = r.Outcome, r.ExitCode, r.DataSha256, r.PolicySha256 });
        }
        Case("clean-unacknowledged", "HOLD", false, b => Fixtures.Decision(b));
        Case("clean-acknowledged", "ADMIT", true, b => Fixtures.Decision(b));
        Case("missing-stale", "REJECT", false, b =>
        {
            File.WriteAllBytes(Path.Combine(b, "input.csv"), Encoding.UTF8.GetBytes(Fixtures.Csv([Fixtures.Grid[0]])));
            File.WriteAllBytes(Path.Combine(b, "policy.json"), Fixtures.PolicyBytes("2026-01-01T00:20:00Z"));
        });
        Case("wrong-binding", "REJECT", false, b => Fixtures.Decision(b, datasetHash: new string('0', 64)));
        Case("license-denied", "REJECT", true, b => Fixtures.Decision(b, license: "deny"));
        if (reports[0].Provenance.Status != "UNKNOWN" || reports[0].UseLicense.Status != "UNKNOWN" || reports[1].Provenance.Basis != "OWNER_DECISION_ACCEPTED" || reports[2].Coverage.Status != "FAIL" || reports[2].Freshness.Status != "FAIL" || reports[3].DecisionBindingMatches != false || reports[4].UseLicense.Status != "FAIL") throw new Problem("DEMO_ASSERTION_FAILED");
        var result = new { schema = "data-admission-demo-v1", version = Contract.Version, toolBuild = Contract.Build, complete = true, outcome = "EXPECTED_OUTCOMES_OBSERVED", cases, identity = "NOT_PROVEN", authenticity = "NOT_PROVEN", legalRights = "NOT_PROVEN", originalSoftwareLicense = "MIT", limits = "Five generated synthetic cases only; demo success means expected HOLD/ADMIT/REJECT observations, not actual origin/rights, live freshness or external completeness proof." };
        byte[] json = Encoding.UTF8.GetBytes(Contract.Serialize(result) + "\n"); if (json.Length > Contract.JsonOutputLimit) throw new Problem("REPORT_BYTE_LIMIT"); Safe.Owned(destination, nonce);
        Safe.WriteNew(Path.Combine(destination, "summary.txt.pending"), Encoding.UTF8.GetBytes("Data Admission Gate demo: expected outcomes observed\nHOLD, ADMIT under synthetic owner assertion, REJECT missing/stale, REJECT wrong binding, REJECT license denial.\nNot verified identity/authenticity/rights; original software MIT; input rights remain unproven.\n"));
        Safe.WriteNew(Path.Combine(destination, "summary.json.pending"), json); Safe.Owned(destination, nonce); File.Move(Path.Combine(destination, "summary.txt.pending"), Path.Combine(destination, "summary.txt")); File.Move(Path.Combine(destination, "summary.json.pending"), Path.Combine(destination, "summary.json")); return result;
    }
}
