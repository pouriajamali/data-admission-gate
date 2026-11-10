using System.Text.Json;

namespace DataAdmission;
internal static class VendorPins
{
    internal static readonly Dictionary<string, (string Path, string Blob, int Bytes, string Sha)> Expected = new(StringComparer.Ordinal)
    {
        ["CsvContract.cs"] = ("src/Integrity/CsvContract.cs", "6ad8ed023f6c8a30f7c8e6a70c5d7c249c0c91aa", 7475, "7deaf13af27054f178948fa18f0768fb3be290e2a4888f131536e75a057a288f"),
        ["CsvValidator.cs"] = ("src/Integrity/CsvValidator.cs", "2b0cc21ef232e74afb2d9e89828d0718714621cb", 7081, "48d89c4553b619d80f8997e27233075ff0f76eb3410859735834c7454ec084a0"),
        ["Contracts.cs"] = ("src/Integrity/Contracts.cs", "8330babc7673ff51d070549bea8fdba482b875c6", 6844, "3327218bf7ad83861ff2498cff4f9687248d0343e98564827b38921c1593fa60"),
        ["BoundedReader.cs"] = ("src/Integrity/BoundedReader.cs", "db3616d4b81f6d958da65c3b70b219974bb9719e", 2266, "f2c7b639509aafed2fe66cfc6364f89f6962e5a66506a4ae05237911e1f8ca05"),
        ["LICENSE"] = ("LICENSE", "e67e64a5ab7fcec5def82845d73fc7f96f82c9ba", 1070, "64a019c3d9ae2e3f44fa8e3de6f91fd762ca917cbad6339401baace445f7ff83")
    };
    public static void Check(string? directory = null)
    {
        directory ??= Path.Combine(AppContext.BaseDirectory, "vendor", "integrity-csv");
        Safe.NoLinks(directory);
        var names = Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).ToArray();
        if (names.Length != 6 || !names.ToHashSet(StringComparer.Ordinal).SetEquals(Expected.Keys.Append("PINS.json")))
            throw new Problem("VENDOR_PIN_INVALID");
        foreach (var p in Expected)
        {
            byte[] bytes = Safe.Read(Path.Combine(directory, p.Key), 16384);
            if (bytes.Length != p.Value.Bytes || Contract.Hash(bytes) != p.Value.Sha)
                throw new Problem("VENDOR_PIN_INVALID");
        }

        using var d = Contract.Document(Safe.Read(Path.Combine(directory, "PINS.json"), 16384), 16384);
        var r = d.RootElement;
        Contract.Fields(r, "commit", "files");
        if (Contract.Text(r, "commit") != Contract.VendorRevision)
            throw new Problem("VENDOR_PIN_INVALID");
        var files = r.GetProperty("files");
        if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() != 5)
            throw new Problem("VENDOR_PIN_INVALID");
        HashSet<string> seen = [];
        foreach (var f in files.EnumerateArray())
        {
            Contract.Fields(f, "file", "sourcePath", "gitBlob", "bytes", "sha256");
            string name = Contract.Text(f, "file");
            if (!seen.Add(name) || !Expected.TryGetValue(name, out var p) || Contract.Text(f, "sourcePath") != p.Path || Contract.Text(f, "gitBlob") != p.Blob || Contract.Integer(f, "bytes") != p.Bytes || Contract.Text(f, "sha256") != p.Sha)
                throw new Problem("VENDOR_PIN_INVALID");
        }
    }
}
