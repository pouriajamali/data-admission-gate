using System.Runtime.InteropServices;
using System.Text;

namespace DataAdmission;

// Adapted from the author's public MIT Release Doctor / Reconciliation Ledger;
// see NOTICE.md and retained third-party licenses.
internal static class Safe
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx { [FieldOffset(0)] public uint Mask; [FieldOffset(28)] public ushort Mode; }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int LinuxStatx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Statx result);
    public static void NoLinks(string path)
    {
        string? p = Path.GetFullPath(path);
        while (p != null)
        {
            FileSystemInfo f = Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p);
            if (f.LinkTarget != null || f.Exists && (f.Attributes & FileAttributes.ReparsePoint) != 0) throw new Problem("LINK_UNSUPPORTED"); p = Path.GetDirectoryName(p);
        }
    }
    public static string Normalize(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Any(c => char.IsControl(c) || c is '\u2028' or '\u2029' or '\ufeff') || path.StartsWith("//") || path.StartsWith(@"\\") || !OperatingSystem.IsWindows() && path.Contains('\\')) throw new Problem("PATH_UNSUPPORTED");
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)); if (full.Length > 384 || full.StartsWith(@"\\")) throw new Problem("PATH_UNSUPPORTED");
        if (OperatingSystem.IsWindows() && new DriveInfo(Path.GetPathRoot(full)!).DriveType == DriveType.Network) throw new Problem("NETWORK_PATH_UNSUPPORTED"); NoLinks(full); return full;
    }
    public static void Regular(string path)
    {
        NoLinks(path); if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0) throw new Problem("REGULAR_FILE_REQUIRED");
        if (OperatingSystem.IsLinux() && (LinuxStatx(-100, path, 0x100, 1, out var s) != 0 || (s.Mask & 1) == 0 || (s.Mode & 0xf000) != 0x8000)) throw new Problem("REGULAR_FILE_REQUIRED");
    }
    public static byte[] Read(string path, int cap)
    {
        path = Normalize(path); Regular(path); var before = new FileInfo(path); long length = before.Length, ticks = before.LastWriteTimeUtc.Ticks; if (length > cap) throw new Problem("INPUT_BYTE_LIMIT");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); using var output = new MemoryStream(); byte[] buffer = new byte[8192]; int count;
        while ((count = stream.Read(buffer)) > 0) { if (output.Length + count > cap) throw new Problem("INPUT_BYTE_LIMIT"); output.Write(buffer, 0, count); }
        Regular(path); var after = new FileInfo(path); if (output.Length != length || after.Length != length || after.LastWriteTimeUtc.Ticks != ticks) throw new Problem("INPUT_CHANGED"); return output.ToArray();
    }
    public static bool Nested(string a, string b)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal; string prefix = Path.EndsInDirectorySeparator(b) ? b : b + Path.DirectorySeparatorChar;
        return a.Equals(b, comparison) || a.StartsWith(prefix, comparison);
    }
    public static void Separate(string a, string b) { if (Nested(a, b) || Nested(b, a)) throw new Problem("OUTPUT_OVERLAPS_INPUT"); }
    public static void WriteNew(string path, byte[] bytes) { NoLinks(path); using var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write); f.Write(bytes); }
    public static void Fresh(string path, string nonce)
    {
        Contract.Nonce(nonce); NoLinks(path); if (Directory.Exists(path) || File.Exists(path)) throw new Problem("OUTPUT_EXISTS"); Directory.CreateDirectory(path); NoLinks(path); WriteNew(Path.Combine(path, ".admission-owned"), Encoding.ASCII.GetBytes(nonce));
    }
    public static void Owned(string path, string nonce)
    { NoLinks(path); if (!Read(Path.Combine(path, ".admission-owned"), 32).SequenceEqual(Encoding.ASCII.GetBytes(Contract.Nonce(nonce)))) throw new Problem("OWNERSHIP_CHANGED"); }
}

internal sealed class Bundle
{
    public string Root { get; }
    public Dictionary<string, byte[]> Files { get; }
    private static readonly Dictionary<string, int> Caps = new(StringComparer.Ordinal) { ["input.csv"] = Contract.InputLimit, ["policy.json"] = Contract.PolicyLimit, ["owner-decision.json"] = Contract.DecisionLimit };
    private Bundle(string root, Dictionary<string, byte[]> files) { Root = root; Files = files; }
    public static Bundle Capture(string directory)
    {
        directory = Safe.Normalize(directory); if (!Directory.Exists(directory)) throw new Problem("BUNDLE_REQUIRED"); Dictionary<string, byte[]> files = new(StringComparer.Ordinal); int count = 0;
        foreach (string path in Directory.EnumerateFileSystemEntries(directory))
        {
            if (++count > 3) throw new Problem("BUNDLE_ENTRY_LIMIT"); string name = Path.GetFileName(path);
            if (!Caps.TryGetValue(name, out int cap) || files.ContainsKey(name)) throw new Problem("BUNDLE_MEMBER_UNSUPPORTED"); files.Add(name, Safe.Read(path, cap));
        }
        if (!files.ContainsKey("input.csv") || !files.ContainsKey("policy.json")) throw new Problem("BUNDLE_REQUIRED_MEMBER_MISSING");
        return new(directory, files);
    }
    public string Hash(string name) => Contract.Hash(Files[name]);
    public void Recheck()
    {
        try
        {
            var now = Capture(Root);
            if (now.Files.Count != Files.Count || Files.Any(p => !now.Files.TryGetValue(p.Key, out var bytes) || !p.Value.SequenceEqual(bytes))) throw new Problem("INPUT_CHANGED");
        }
        catch (Exception e) when (e is not OutOfMemoryException) { throw new Problem("INPUT_CHANGED"); }
    }
}
