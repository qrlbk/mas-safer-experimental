// Local hardening patch. Does not change license generation or activation protocols.
namespace LibTSforge
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.AccessControl;

    // A batch is explicit: disposing after an exception NEVER saves pending data.
    // A failed Windows replacement may already have moved its destination.
    // Recovery is best-effort per file, not a transaction across power loss.
    public sealed class StoreWriteBatch : IDisposable
    {
        [ThreadStatic] private static StoreWriteBatch active;
        private readonly List<string> paths = new List<string>();
        private readonly List<byte[]> contents = new List<byte[]>();
        private bool finished;

        public StoreWriteBatch()
        {
            if (active != null) throw new InvalidOperationException("Nested store write batch.");
            active = this;
        }

        private static void CheckPath(string path)
        {
            CheckPath(path, false);
        }

        private static void CheckPath(string path, bool allowMissingLeaf)
        {
            bool leaf = true;
            for (string p = Path.GetFullPath(path); !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p))
            {
                try
                {
                    FileAttributes attributes = File.GetAttributes(p);
                    if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                        (leaf && (attributes & FileAttributes.Directory) != 0))
                        throw new IOException("Refusing a redirected/non-file store path: " + p);
                }
                catch (FileNotFoundException) { if (!leaf || !allowMissingLeaf) throw; }
                catch (DirectoryNotFoundException) { if (!leaf || !allowMissingLeaf) throw; }
                leaf = false;
            }
        }

        public static void Write(FileStream[] files, byte[][] data)
        {
            if (files.Length != data.Length || files.Length == 0) throw new ArgumentException("Invalid write set.");
            string[] names = files.Select(f => f.Name).ToArray();
            for (int i = 0; i < names.Length; i++) CheckPath(names[i]);
            // Data has already been serialized/encrypted successfully. Release the locks only now.
            foreach (FileStream file in files) file.Close();
            if (active != null)
            {
                for (int i = 0; i < names.Length; i++)
                {
                    if (active.paths.Contains(names[i])) throw new InvalidOperationException("Duplicate store path.");
                    active.paths.Add(names[i]);
                    active.contents.Add(data[i]);
                }
            }
            else ReplaceAll(names, data);
        }

        public void Commit()
        {
            if (finished || active != this) throw new InvalidOperationException("Inactive store batch.");
            try { ReplaceAll(paths.ToArray(), contents.ToArray()); }
            finally { finished = true; active = null; }
        }

        private static void ApplyPermissions(string path, string dacl)
        {
            // A fresh descriptor marks the DACL as modified for SetAccessControl.
            // Do not attempt to assign another account as owner of staging files.
            FileSecurity security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(dacl, AccessControlSections.Access);
            new FileInfo(path).SetAccessControl(security);
        }

        private static void ReplaceAll(string[] names, byte[][] data)
        {
            string suffix = ".mas-safer-" + Guid.NewGuid().ToString("N");
            string[] temporary = names.Select(n => n + suffix + ".tmp").ToArray();
            string[] backups = names.Select(n => n + suffix + ".bak").ToArray();
            string[] displaced = names.Select(n => n + suffix + ".displaced").ToArray();
            string[] permissions = new string[names.Length];
            int attempted = 0;
            bool committed = false;
            RecoveryJournal journal = new RecoveryJournal("TSforge-store-files");
            try
            {
                // Independent, verified backups survive partial failures inside File.Replace.
                // Stage ALL outputs and backups before touching ANY destination.
                for (int i = 0; i < names.Length; i++)
                {
                    CheckPath(names[i]);
                    permissions[i] = new FileInfo(names[i]).GetAccessControl(AccessControlSections.Access)
                        .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                    File.Copy(names[i], backups[i], false);
                    ApplyPermissions(backups[i], permissions[i]);
                    if (!File.ReadAllBytes(backups[i]).SequenceEqual(File.ReadAllBytes(names[i])))
                        throw new IOException("Store backup verification failed.");
                    using (FileStream output = new FileStream(temporary[i], FileMode.CreateNew,
                        FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    {
                        output.Write(data[i], 0, data[i].Length);
                        output.Flush();
                    }
                    ApplyPermissions(temporary[i], permissions[i]);
                    if (!File.ReadAllBytes(temporary[i]).SequenceEqual(data[i]))
                        throw new IOException("Staged store verification failed.");
                    journal.Required("backup-verified", names[i], backups[i], "",
                        RecoveryJournal.Hash(File.ReadAllBytes(backups[i])), "original-bytes");
                    journal.Required("output-staged", names[i], backups[i], temporary[i],
                        RecoveryJournal.Hash(data[i]), "no-destination-change-yet");
                }
                for (int i = 0; i < names.Length; i++)
                {
                    CheckPath(names[i]);
                    if (!File.ReadAllBytes(names[i]).SequenceEqual(File.ReadAllBytes(backups[i])))
                        throw new IOException("Store changed after staging; refusing replacement.");
                    journal.Required("replace-intent", names[i], backups[i], displaced[i], "", "may-partially-complete");
                    attempted = i + 1; // Include partial failure INSIDE the native call.
                    File.Replace(temporary[i], names[i], displaced[i]);
                    journal.Note("replace-returned", names[i], backups[i], "", "", "file-operation-only");
                }
                committed = true;
                journal.Note("files-committed", "", "", "", "", "activation-not-verified");
            }
            catch (Exception writeError)
            {
                string rollbackErrors = "";
                journal.Note("operation-failed", "", "", "", "", writeError.GetType().FullName);
                for (int i = attempted - 1; i >= 0; i--)
                {
                    string restore = names[i] + suffix + ".restore";
                    try
                    {
                        journal.Note("rollback-intent", names[i], backups[i], restore, "", "recovery-pending");
                        CheckPath(names[i], true);
                        CheckPath(backups[i]);
                        if (File.Exists(names[i]) && File.ReadAllBytes(names[i]).SequenceEqual(File.ReadAllBytes(backups[i])))
                        {
                            journal.Note("rollback-item", names[i], backups[i], "", "", "unchanged");
                            continue; // Failed before mutation; leave the original in place.
                        }
                        File.Copy(backups[i], restore, false);
                        ApplyPermissions(restore, permissions[i]);
                        if (!File.ReadAllBytes(restore).SequenceEqual(File.ReadAllBytes(backups[i])))
                            throw new IOException("Recovery staging verification failed.");
                        CheckPath(names[i], true);
                        if (File.Exists(names[i]))
                            File.Replace(restore, names[i], names[i] + suffix + ".rollback-displaced");
                        else
                            File.Move(restore, names[i]);
                        journal.Note("rollback-item", names[i], backups[i], restore, "", "restored");
                    }
                    catch (Exception ex)
                    {
                        rollbackErrors += " " + names[i] + ": " + ex.Message;
                        journal.Note("rollback-item", names[i], backups[i], restore, "", "manual-recovery:" + ex.GetType().FullName);
                    }
                }
                journal.Note("file-rollback-ended", "", "", "", "",
                    rollbackErrors.Length == 0 ? "restored-or-unchanged; licensing-state-not-restored" : "manual-recovery-required");
                throw new IOException("Store write failed. Backups retained with suffix " + suffix +
                    (rollbackErrors.Length == 0 ? ". Attempted file replacements restored or unchanged; licensing API/registry changes are not rolled back." :
                    ". MANUAL RECOVERY REQUIRED:" + rollbackErrors), writeError);
            }
            finally
            {
                // Retain all recovery artifacts on failure, including a partial rollback.
                if (committed) foreach (string path in temporary.Concat(displaced))
                {
                    try { if (File.Exists(path)) File.Delete(path); }
                    catch (Exception cleanupError) { journal.Note("cleanup-retained", path, "", "", "", cleanupError.GetType().FullName); }
                }
            }
        }

        public void Dispose()
        {
            if (active == this) active = null;
            finished = true;
            paths.Clear();
            contents.Clear();
        }
    }
}
