namespace LibTSforge
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;

    public enum PSVersion
    {
        Vista,
        Win7,
        Win8,
        WinBlue,
        WinModern
    }

    public static class Constants
    {
        public static readonly byte[] UniversalHWIDBlock =
        {
            0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x0c, 0x01, 0x00
        };

        public static readonly byte[] KMSv4Response =
        {
            0x00, 0x00, 0x04, 0x00, 0x62, 0x00, 0x00, 0x00, 0x30, 0x00, 0x35, 0x00, 0x34, 0x00, 0x32, 0x00,
            0x36, 0x00, 0x2D, 0x00, 0x30, 0x00, 0x30, 0x00, 0x32, 0x00, 0x30, 0x00, 0x36, 0x00, 0x2D, 0x00,
            0x31, 0x00, 0x36, 0x00, 0x31, 0x00, 0x2D, 0x00, 0x36, 0x00, 0x35, 0x00, 0x35, 0x00, 0x35, 0x00,
            0x30, 0x00, 0x36, 0x00, 0x2D, 0x00, 0x30, 0x00, 0x33, 0x00, 0x2D, 0x00, 0x31, 0x00, 0x30, 0x00,
            0x33, 0x00, 0x33, 0x00, 0x2D, 0x00, 0x39, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2E, 0x00,
            0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2D, 0x00, 0x30, 0x00, 0x36, 0x00, 0x35, 0x00,
            0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x33, 0x00, 0x00, 0x00, 0xDE, 0x19, 0x02, 0xCF, 0x1F, 0x35,
            0x97, 0x4E, 0x8A, 0x8F, 0xB8, 0x07, 0xB1, 0x92, 0xB5, 0xB5, 0x97, 0x42, 0xEC, 0x3A, 0x76, 0x84,
            0xD5, 0x01, 0x32, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x60, 0x27, 0x00, 0x00, 0xC4, 0x1E,
            0xAA, 0x8B, 0xDD, 0x0C, 0xAB, 0x55, 0x6A, 0xCE, 0xAF, 0xAC, 0x7F, 0x5F, 0xBD, 0xE9
        };

        public static readonly byte[] KMSv5Response =
        {
            0x00, 0x00, 0x05, 0x00, 0xBE, 0x96, 0xF9, 0x04, 0x54, 0x17, 0x3F, 0xAF, 0xE3, 0x08, 0x50, 0xEB,
            0x22, 0xBA, 0x53, 0xBF, 0xF2, 0x6A, 0x7B, 0xC9, 0x05, 0x1D, 0xB5, 0x19, 0xDF, 0x98, 0xE2, 0x71,
            0x4D, 0x00, 0x61, 0xE9, 0x9D, 0x03, 0xFB, 0x31, 0xF9, 0x1F, 0x2E, 0x60, 0x59, 0xC7, 0x73, 0xC8,
            0xE8, 0xB6, 0xE1, 0x2B, 0x39, 0xC6, 0x35, 0x0E, 0x68, 0x7A, 0xAA, 0x4F, 0x28, 0x23, 0x12, 0x18,
            0xE3, 0xAA, 0x84, 0x81, 0x6E, 0x82, 0xF0, 0x3F, 0xD9, 0x69, 0xA9, 0xDF, 0xBA, 0x5F, 0xCA, 0x32,
            0x54, 0xB2, 0x52, 0x3B, 0x3E, 0xD1, 0x5C, 0x65, 0xBC, 0x3E, 0x59, 0x0D, 0x15, 0x9F, 0x37, 0xEC,
            0x30, 0x9C, 0xCC, 0x1B, 0x39, 0x0D, 0x21, 0x32, 0x29, 0xA2, 0xDD, 0xC7, 0xC1, 0x69, 0xF2, 0x72,
            0x3F, 0x00, 0x98, 0x1E, 0xF8, 0x9A, 0x79, 0x44, 0x5D, 0x25, 0x80, 0x7B, 0xF5, 0xE1, 0x7C, 0x68,
            0x25, 0xAA, 0x0D, 0x67, 0x98, 0xE5, 0x59, 0x9B, 0x04, 0xC1, 0x23, 0x33, 0x48, 0xFB, 0x28, 0xD0,
            0x76, 0xDF, 0x01, 0x56, 0xE7, 0xEC, 0xBF, 0x1A, 0xA2, 0x22, 0x28, 0xCA, 0xB1, 0xB4, 0x4C, 0x30,
            0x14, 0x6F, 0xD2, 0x2E, 0x01, 0x2A, 0x04, 0xE3, 0xBD, 0xA7, 0x41, 0x2F, 0xC9, 0xEF, 0x53, 0xC0,
            0x70, 0x48, 0xF1, 0xB2, 0xB6, 0xEA, 0xE7, 0x0F, 0x7A, 0x15, 0xD1, 0xA6, 0xFE, 0x23, 0xC8, 0xF3,
            0xE1, 0x02, 0x9E, 0xA0, 0x4E, 0xBD, 0xF5, 0xEA, 0x53, 0x74, 0x8E, 0x74, 0xA1, 0xA1, 0xBD, 0xBE,
            0x66, 0xC4, 0x73, 0x8F, 0x24, 0xA7, 0x2A, 0x2F, 0xE3, 0xD9, 0xF4, 0x28, 0xD9, 0xF8, 0xA3, 0x93,
            0x03, 0x9E, 0x29, 0xAB
        };

        public static readonly byte[] KMSv6Response =
        {
            0x00, 0x00, 0x06, 0x00, 0x54, 0xD3, 0x40, 0x08, 0xF3, 0xCD, 0x03, 0xEF, 0xC8, 0x15, 0x87, 0x9E,
            0xCA, 0x2E, 0x85, 0xFB, 0xE6, 0xF6, 0x73, 0x66, 0xFB, 0xDA, 0xBB, 0x7B, 0xB1, 0xBC, 0xD6, 0xF9,
            0x5C, 0x41, 0xA0, 0xFE, 0xE1, 0x74, 0xC4, 0xBB, 0x91, 0xE5, 0xDE, 0x6D, 0x3A, 0x11, 0xD5, 0xFC,
            0x68, 0xC0, 0x7B, 0x82, 0xB2, 0x24, 0xD1, 0x85, 0xBA, 0x45, 0xBF, 0xF1, 0x26, 0xFA, 0xA5, 0xC6,
            0x61, 0x70, 0x69, 0x69, 0x6E, 0x0F, 0x0B, 0x60, 0xB7, 0x3D, 0xE8, 0xF1, 0x47, 0x0B, 0x65, 0xFD,
            0xA7, 0x30, 0x1E, 0xF6, 0xA4, 0xD0, 0x79, 0xC4, 0x58, 0x8D, 0x81, 0xFD, 0xA7, 0xE7, 0x53, 0xF1,
            0x67, 0x78, 0xF0, 0x0F, 0x60, 0x8F, 0xC8, 0x16, 0x35, 0x22, 0x94, 0x48, 0xCB, 0x0F, 0x8E, 0xB2,
            0x1D, 0xF7, 0x3E, 0x28, 0x42, 0x55, 0x6B, 0x07, 0xE3, 0xE8, 0x51, 0xD5, 0xFA, 0x22, 0x0C, 0x86,
            0x65, 0x0D, 0x3F, 0xDD, 0x8D, 0x9B, 0x1B, 0xC9, 0xD3, 0xB8, 0x3A, 0xEC, 0xF1, 0x11, 0x19, 0x25,
            0xF7, 0x84, 0x4A, 0x4C, 0x0A, 0xB5, 0x31, 0x94, 0x37, 0x76, 0xCE, 0xE7, 0xAB, 0xA9, 0x69, 0xDF,
            0xA4, 0xC9, 0x22, 0x6C, 0x23, 0xFF, 0x6B, 0xFC, 0xDA, 0x78, 0xD8, 0xC4, 0x8F, 0x74, 0xBB, 0x26,
            0x05, 0x00, 0x98, 0x9B, 0xE5, 0xE2, 0xAD, 0x0D, 0x57, 0x95, 0x80, 0x66, 0x8E, 0x43, 0x74, 0x87,
            0x93, 0x1F, 0xF4, 0xB2, 0x2C, 0x20, 0x5F, 0xD8, 0x9C, 0x4C, 0x56, 0xB3, 0x57, 0x44, 0x62, 0x68,
            0x8D, 0xAA, 0x40, 0x11, 0x9D, 0x84, 0x62, 0x0E, 0x43, 0x8A, 0x1D, 0xF0, 0x1C, 0x49, 0xD8, 0x56,
            0xEF, 0x4C, 0xD3, 0x64, 0xBA, 0x0D, 0xEF, 0x87, 0xB5, 0x2C, 0x88, 0xF3, 0x18, 0xFF, 0x3A, 0x8C,
            0xF5, 0xA6, 0x78, 0x5C, 0x62, 0xE3, 0x9E, 0x4C, 0xB6, 0x31, 0x2D, 0x06, 0x80, 0x92, 0xBC, 0x2E,
            0x92, 0xA6, 0x56, 0x96
        };

        // 2^31 - 8 minutes
        public static readonly ulong TimerMax = (ulong)TimeSpan.FromMinutes(2147483640).Ticks;

        public static readonly string ZeroCID = new string('0', 48);
    }

    public static class BinaryReaderExt
    {
        public static void Align(this BinaryReader reader, int to)
        {
            int pos = (int)reader.BaseStream.Position;
            reader.BaseStream.Seek(-pos & (to - 1), SeekOrigin.Current);
        }

        public static string ReadNullTerminatedString(this BinaryReader reader, int maxLen)
        {
            return Encoding.Unicode.GetString(reader.ReadBytes(maxLen)).Split(new char[] { '\0' }, 2)[0];
        }
    }

    public static class BinaryWriterExt
    {
        public static void Align(this BinaryWriter writer, int to)
        {
            int pos = (int)writer.BaseStream.Position;
            writer.WritePadding(-pos & (to - 1));
        }

        public static void WritePadding(this BinaryWriter writer, int len)
        {
            writer.Write(Enumerable.Repeat((byte)0, len).ToArray());
        }

        public static void WriteFixedString(this BinaryWriter writer, string str, int bLen)
        {
            writer.Write(Encoding.ASCII.GetBytes(str));
            writer.WritePadding(bLen - str.Length);
        }

        public static void WriteFixedString16(this BinaryWriter writer, string str, int bLen)
        {
            byte[] bstr = Utils.EncodeString(str);
            writer.Write(bstr);
            writer.WritePadding(bLen - bstr.Length);
        }

        public static byte[] GetBytes(this BinaryWriter writer)
        {
            return ((MemoryStream)writer.BaseStream).ToArray();
        }
    }

    public static class ByteArrayExt
    {
        public static byte[] CastToArray<T>(this T data) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] result = new byte[size];
            GCHandle handle = GCHandle.Alloc(result, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(data, handle.AddrOfPinnedObject(), false);
            }
            finally
            {
                handle.Free();
            }
            return result;
        }
    }

    public static class FileStreamExt
    {
        public static byte[] ReadAllBytes(this FileStream fs)
        {
            BinaryReader br = new BinaryReader(fs);
            return br.ReadBytes((int)fs.Length);
        }

        public static void WriteAllBytes(this FileStream fs, byte[] data)
        {
            fs.Seek(0, SeekOrigin.Begin);
            fs.SetLength(data.Length);
            fs.Write(data, 0, data.Length);
        }
    }

    public static class Utils
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetSystemDefaultLCID();

        [DllImport("kernel32.dll")]
        public static extern bool Wow64EnableWow64FsRedirection(bool Wow64FsEnableRedirection);

        public static string DecodeString(byte[] data)
        {
            return Encoding.Unicode.GetString(data).Trim('\0');
        }

        public static byte[] EncodeString(string str)
        {
            return Encoding.Unicode.GetBytes(str + '\0');
        }

        public static uint CRC32(byte[] data)
        {
            const uint polynomial = 0x04C11DB7;
            uint crc = 0xffffffff;

            foreach (byte b in data)
            {
                crc ^= (uint)b << 24;
                for (int bit = 0; bit < 8; bit++)
                {
                    if ((crc & 0x80000000) != 0)
                    {
                        crc = (crc << 1) ^ polynomial;
                    }
                    else
                    {
                        crc <<= 1;
                    }
                }
            }
            return ~crc;
        }

        public static string GetArchitecture()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE", EnvironmentVariableTarget.Machine).ToUpperInvariant();
            return arch == "AMD64" ? "X64" : arch;
        }

        public static PSVersion DetectVersion()
        {
            int build = Environment.OSVersion.Version.Build;

            if (build >= 9600) return PSVersion.WinModern;
            if (build >= 6000 && build <= 6003) return PSVersion.Vista;
            if (build >= 7600 && build <= 7602) return PSVersion.Win7;
            if (build == 9200) return PSVersion.Win8;

            throw new NotSupportedException("Unable to auto-detect version info");
        }
    }

    public static class Logger
    {
        public static bool HideOutput = false;

        public static void WriteLine(string line)
        {
            if (!HideOutput) Console.WriteLine(line);
        }
    }
}
namespace LibTSforge.Crypto
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    public static class CryptoUtils
    {
        public static byte[] GenerateRandomKey(int len)
        {
            byte[] rand = new byte[len];
            Random r = new Random();
            r.NextBytes(rand);

            return rand;
        }

        public static byte[] AESEncrypt(byte[] data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, Enumerable.Repeat((byte)0, 16).ToArray());
                byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                return encryptedData;
            }
        }

        public static byte[] AESDecrypt(byte[] data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, Enumerable.Repeat((byte)0, 16).ToArray());
                byte[] decryptedData = decryptor.TransformFinalBlock(data, 0, data.Length);
                return decryptedData;
            }
        }

        public static byte[] RSADecrypt(byte[] rsaKey, byte[] data)
        {

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(rsaKey);
                return rsa.Decrypt(data, false);
            }
        }

        public static byte[] RSAEncrypt(byte[] rsaKey, byte[] data)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(rsaKey);
                return rsa.Encrypt(data, false);
            }
        }

        public static byte[] RSASign(byte[] rsaKey, byte[] data)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(rsaKey);
                RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(rsa);
                formatter.SetHashAlgorithm("SHA1");

                byte[] hash;
                using (SHA1 sha1 = SHA1.Create())
                {
                    hash = sha1.ComputeHash(data);
                }

                return formatter.CreateSignature(hash);
            }
        }

        public static bool RSAVerifySignature(byte[] rsaKey, byte[] data, byte[] signature)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(rsaKey);
                RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(rsa);
                deformatter.SetHashAlgorithm("SHA1");

                byte[] hash;
                using (SHA1 sha1 = SHA1.Create())
                {
                    hash = sha1.ComputeHash(data);
                }

                return deformatter.VerifySignature(hash, signature);
            }
        }

        public static byte[] HMACSign(byte[] key, byte[] data)
        {
            HMACSHA1 hmac = new HMACSHA1(key);
            return hmac.ComputeHash(data);
        }

        public static bool HMACVerify(byte[] key, byte[] data, byte[] signature)
        {
            return Enumerable.SequenceEqual(signature, HMACSign(key, data));
        }

        public static byte[] SaltSHASum(byte[] salt, byte[] data)
        {
            SHA1 sha1 = SHA1.Create();
            byte[] sha_data = salt.Concat(data).ToArray();
            return sha1.ComputeHash(sha_data);
        }

        public static bool SaltSHAVerify(byte[] salt, byte[] data, byte[] checksum)
        {
            return Enumerable.SequenceEqual(checksum, SaltSHASum(salt, data));
        }

        public static byte[] SHA256Hash(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }
    }
}
namespace LibTSforge.TokenStore
{
    using System.Collections.Generic;
    using System.IO;

    public class TokenEntry
    {
        public string Name;
        public string Extension;
        public byte[] Data;
        public bool Populated;
    }

    public class TokenMeta
    {
        public string Name;
        public readonly Dictionary<string, string> Data = new Dictionary<string, string>();

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(1);
            byte[] nameBytes = Utils.EncodeString(Name);
            writer.Write(nameBytes.Length);
            writer.Write(nameBytes);

            foreach (KeyValuePair<string, string> kv in Data)
            {
                byte[] keyBytes = Utils.EncodeString(kv.Key);
                byte[] valueBytes = Utils.EncodeString(kv.Value);
                writer.Write(keyBytes.Length);
                writer.Write(valueBytes.Length);
                writer.Write(keyBytes);
                writer.Write(valueBytes);
            }

            return writer.GetBytes();
        }

        private void Deserialize(byte[] data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            reader.ReadInt32();
            int nameLen = reader.ReadInt32();
            Name = reader.ReadNullTerminatedString(nameLen);

            while (reader.BaseStream.Position < data.Length - 0x8)
            {
                int keyLen = reader.ReadInt32();
                int valueLen = reader.ReadInt32();
                string key = reader.ReadNullTerminatedString(keyLen);
                string value = reader.ReadNullTerminatedString(valueLen);
                Data[key] = value;
            }
        }

        public TokenMeta(byte[] data)
        {
            Deserialize(data);
        }

        public TokenMeta()
        {

        }
    }
}


// LibTSforge/TokenStore/ITokenStore.cs
namespace LibTSforge.TokenStore
{
    using System;

    public interface ITokenStore : IDisposable
    {
        void Deserialize();
        void Serialize();
        void AddEntry(TokenEntry entry);
        void AddEntries(TokenEntry[] entries);
        void DeleteEntry(string name, string ext);
        void DeleteUnpopEntry(string name, string ext);
        TokenEntry GetEntry(string name, string ext);
        TokenMeta GetMetaEntry(string name);
        void SetEntry(string name, string ext, byte[] data);
    }
}


// LibTSforge/TokenStore/TokenStoreModern.cs
namespace LibTSforge.TokenStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using Crypto;

    public class TokenStoreModern : ITokenStore
    {
        private static readonly uint VERSION = 3;
        private static readonly int ENTRY_SIZE = 0x9E;
        private static readonly int BLOCK_SIZE = 0x4020;
        private static readonly int ENTRIES_PER_BLOCK = BLOCK_SIZE / ENTRY_SIZE;
        private static readonly int BLOCK_PAD_SIZE = 0x66;

        private static readonly byte[] CONTS_HEADER = Enumerable.Repeat((byte)0x55, 0x20).ToArray();
        private static readonly byte[] CONTS_FOOTER = Enumerable.Repeat((byte)0xAA, 0x20).ToArray();

        private List<TokenEntry> Entries = new List<TokenEntry>();
        private readonly FileStream TokensFile;

        public void Deserialize()
        {
            if (TokensFile.Length < BLOCK_SIZE) return;

            TokensFile.Seek(0x24, SeekOrigin.Begin);
            uint nextBlock;

            BinaryReader reader = new BinaryReader(TokensFile);
            do
            {
                reader.ReadUInt32();
                nextBlock = reader.ReadUInt32();

                for (int i = 0; i < ENTRIES_PER_BLOCK; i++)
                {
                    uint curOffset = reader.ReadUInt32();
                    bool populated = reader.ReadUInt32() == 1;
                    uint contentOffset = reader.ReadUInt32();
                    uint contentLength = reader.ReadUInt32();
                    uint allocLength = reader.ReadUInt32();
                    byte[] contentData = { };

                    if (populated)
                    {
                        reader.BaseStream.Seek(contentOffset + 0x20, SeekOrigin.Begin);
                        uint dataLength = reader.ReadUInt32();

                        if (dataLength != contentLength)
                        {
                            throw new FormatException("Data length in tokens content is inconsistent with entry.");
                        }

                        reader.ReadBytes(0x20);
                        contentData = reader.ReadBytes((int)contentLength);
                    }

                    reader.BaseStream.Seek(curOffset + 0x14, SeekOrigin.Begin);

                    Entries.Add(new TokenEntry
                    {
                        Name = reader.ReadNullTerminatedString(0x82),
                        Extension = reader.ReadNullTerminatedString(0x8),
                        Data = contentData,
                        Populated = populated
                    });
                }

                reader.BaseStream.Seek(nextBlock, SeekOrigin.Begin);
            } while (nextBlock != 0);
        }

        public void Serialize()
        {
            MemoryStream tokens = new MemoryStream();

            using (BinaryWriter writer = new BinaryWriter(tokens))
            {
                writer.Write(VERSION);
                writer.Write(CONTS_HEADER);

                int curBlockOffset = (int)writer.BaseStream.Position;
                int curEntryOffset = curBlockOffset + 0x8;
                int curContsOffset = curBlockOffset + BLOCK_SIZE;

                for (int eIndex = 0; eIndex < ((Entries.Count / ENTRIES_PER_BLOCK) + 1) * ENTRIES_PER_BLOCK; eIndex++)
                {
                    TokenEntry entry;

                    if (eIndex < Entries.Count)
                    {
                        entry = Entries[eIndex];
                    }
                    else
                    {
                        entry = new TokenEntry
                        {
                            Name = "",
                            Extension = "",
                            Populated = false,
                            Data = new byte[] { }
                        };
                    }

                    writer.BaseStream.Seek(curBlockOffset, SeekOrigin.Begin);
                    writer.Write(curBlockOffset);
                    writer.Write(0);

                    writer.BaseStream.Seek(curEntryOffset, SeekOrigin.Begin);
                    writer.Write(curEntryOffset);
                    writer.Write(entry.Populated ? 1 : 0);
                    writer.Write(entry.Populated ? curContsOffset : 0);
                    writer.Write(entry.Populated ? entry.Data.Length : -1);
                    writer.Write(entry.Populated ? entry.Data.Length : -1);
                    writer.WriteFixedString16(entry.Name, 0x82);
                    writer.WriteFixedString16(entry.Extension, 0x8);
                    curEntryOffset = (int)writer.BaseStream.Position;

                    if (entry.Populated)
                    {
                        writer.BaseStream.Seek(curContsOffset, SeekOrigin.Begin);
                        writer.Write(CONTS_HEADER);
                        writer.Write(entry.Data.Length);
                        writer.Write(CryptoUtils.SHA256Hash(entry.Data));
                        writer.Write(entry.Data);
                        writer.Write(CONTS_FOOTER);
                        curContsOffset = (int)writer.BaseStream.Position;
                    }

                    if ((eIndex + 1) % ENTRIES_PER_BLOCK == 0 && eIndex != 0)
                    {
                        if (eIndex < Entries.Count)
                        {
                            writer.BaseStream.Seek(curBlockOffset + 0x4, SeekOrigin.Begin);
                            writer.Write(curContsOffset);
                        }

                        writer.BaseStream.Seek(curEntryOffset, SeekOrigin.Begin);
                        writer.WritePadding(BLOCK_PAD_SIZE);

                        writer.BaseStream.Seek(curBlockOffset, SeekOrigin.Begin);
                        byte[] blockData = new byte[BLOCK_SIZE - 0x20];

                        tokens.Read(blockData, 0, BLOCK_SIZE - 0x20);
                        byte[] blockHash = CryptoUtils.SHA256Hash(blockData);

                        writer.BaseStream.Seek(curBlockOffset + BLOCK_SIZE - 0x20, SeekOrigin.Begin);
                        writer.Write(blockHash);

                        curBlockOffset = curContsOffset;
                        curEntryOffset = curBlockOffset + 0x8;
                        curContsOffset = curBlockOffset + BLOCK_SIZE;
                    }
                }

                tokens.SetLength(curBlockOffset);
            }

            byte[] tokensData = tokens.ToArray();
            byte[] tokensHash = CryptoUtils.SHA256Hash(tokensData.Take(0x4).Concat(tokensData.Skip(0x24)).ToArray());

            tokens = new MemoryStream(tokensData);

            BinaryWriter tokWriter = new BinaryWriter(TokensFile);
            using (BinaryReader reader = new BinaryReader(tokens))
            {
                TokensFile.Seek(0, SeekOrigin.Begin);
                TokensFile.SetLength(tokens.Length);
                tokWriter.Write(reader.ReadBytes(0x4));
                reader.ReadBytes(0x20);
                tokWriter.Write(tokensHash);
                tokWriter.Write(reader.ReadBytes((int)reader.BaseStream.Length - 0x4));
            }
        }

        public void AddEntry(TokenEntry entry)
        {
            Entries.Add(entry);
        }

        public void AddEntries(TokenEntry[] entries)
        {
            Entries.AddRange(entries);
        }

        public void DeleteEntry(string name, string ext)
        {
            foreach (TokenEntry entry in Entries)
            {
                if (entry.Name == name && entry.Extension == ext)
                {
                    Entries.Remove(entry);
                    return;
                }
            }
        }

        public void DeleteUnpopEntry(string name, string ext)
        {
            List<TokenEntry> delEntries = new List<TokenEntry>();
            foreach (TokenEntry entry in Entries)
            {
                if (entry.Name == name && entry.Extension == ext && !entry.Populated)
                {
                    delEntries.Add(entry);
                }
            }

            Entries = Entries.Except(delEntries).ToList();
        }

        public TokenEntry GetEntry(string name, string ext)
        {
            foreach (TokenEntry entry in Entries)
            {
                if (entry.Name == name && entry.Extension == ext)
                {
                    if (!entry.Populated) continue;
                    return entry;
                }
            }

            return null;
        }

        public TokenMeta GetMetaEntry(string name)
        {
            DeleteUnpopEntry(name, "xml");
            TokenEntry entry = GetEntry(name, "xml");
            TokenMeta meta;

            if (entry == null)
            {
                meta = new TokenMeta
                {
                    Name = name
                };
            }
            else
            {
                meta = new TokenMeta(entry.Data);
            }

            return meta;
        }

        public void SetEntry(string name, string ext, byte[] data)
        {
            for (int i = 0; i < Entries.Count; i++)
            {
                TokenEntry entry = Entries[i];

                if (entry.Name == name && entry.Extension == ext && entry.Populated)
                {
                    entry.Data = data;
                    Entries[i] = entry;
                    return;
                }
            }

            Entries.Add(new TokenEntry
            {
                Populated = true,
                Name = name,
                Extension = ext,
                Data = data
            });
        }

        public TokenStoreModern(string tokensPath)
        {
            TokensFile = File.Open(tokensPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            Deserialize();
        }

        public void Dispose()
        {
            Serialize();
            TokensFile.Close();
        }
    }
}