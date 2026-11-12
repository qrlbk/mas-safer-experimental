// Recovery metadata only. Never logs license/key contents or exception messages.
namespace LibTSforge
{
    using System;
    using System.IO;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using System.Text;
    using System.Security.Cryptography;

    public sealed class RecoveryJournal
    {
        private readonly string folder;
        private readonly string scope;
        public string Folder { get { return folder; } }

        private static void CheckDirectory(string path)
        {
            for (string p = Path.GetFullPath(path); !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p))
                if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0 || !Directory.Exists(p))
                    throw new IOException("Redirected or missing recovery directory.");
        }

        public RecoveryJournal(string operationScope)
        {
            scope = operationScope;
            string windows = Environment.GetEnvironmentVariable("windir");
            CheckDirectory(windows);
            string root = Path.Combine(windows, "MAS-Safer-Recovery");
            DirectorySecurity acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544" })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            if (!Directory.Exists(root)) Directory.CreateDirectory(root, acl);
            CheckDirectory(root);
            new DirectoryInfo(root).SetAccessControl(acl);
            folder = Path.Combine(root, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder, acl);
            Required("operation-started", "", "", "", "", "not-completed");
            Console.WriteLine("Recovery journal: " + folder);
        }

        private static string Quote(string value)
        {
            StringBuilder result = new StringBuilder("\"");
            foreach (char c in value ?? "")
            {
                if (c == '"' || c == '\\') { result.Append('\\'); result.Append(c); }
                else if (c < 32) result.Append("\\u" + ((int)c).ToString("x4"));
                else result.Append(c);
            }
            return result.Append('"').ToString();
        }

        public static string Hash(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }

        public void Required(string phase, string item, string backup, string auxiliary, string hash, string result)
        {
            CheckDirectory(folder);
            string path = Path.Combine(folder, "events.jsonl");
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Redirected journal refused.");
            string parent = Environment.GetEnvironmentVariable("MAS_RECOVERY_RUN_ID");
            try { parent = new Guid(parent).ToString("N"); } catch { parent = ""; }
            string json = "{\"schema\":1,\"utc\":" + Quote(DateTime.UtcNow.ToString("o")) +
                ",\"operation\":" + Quote(Path.GetFileName(folder)) + ",\"parent\":" + Quote(parent) +
                ",\"scope\":" + Quote(scope) + ",\"event\":" + Quote(phase) + ",\"item\":" + Quote(item) +
                ",\"backup\":" + Quote(backup) + ",\"auxiliary\":" + Quote(auxiliary) +
                ",\"sha256\":" + Quote(hash) + ",\"result\":" + Quote(result) + "}" + Environment.NewLine;
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            using (FileStream stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush();
            }
        }

        // Logging failure during recovery must never interrupt the recovery itself.
        public void Note(string phase, string item, string backup, string auxiliary, string hash, string result)
        {
            try { Required(phase, item, backup, auxiliary, hash, result); }
            catch
            {
                try { Console.Error.WriteLine("Recovery journal incomplete: " + folder + ". Inspect backups; outcome is unknown."); }
                catch { /* A closed console must not interrupt rollback either. */ }
            }
        }
    }
}
