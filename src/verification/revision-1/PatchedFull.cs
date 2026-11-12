#if !POWERSHELL2
namespace ActivationWs
{

/*

This code is adapted from ActivationWs.
Original Repository: https://github.com/dadorner-msft/activationws

MIT License

Copyright (c) Daniel Dorner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

    public static class ActivationHelper {
        // Key for HMAC/SHA256 signature.
        private static readonly byte[] MacKey = new byte[64] {
            254,  49, 152, 117, 251,  72, 132, 134,
            156, 243, 241, 206, 153, 168, 144, 100,
            171,  87,  31, 202,  71,   4,  80,  88,
            48,   36, 226,  20,  98, 135, 121, 160,
            0,     0,   0,   0,   0,   0,   0,   0,
            0,     0,   0,   0,   0,   0,   0,   0,
            0,     0,   0,   0,   0,   0,   0,   0,
            0,     0,   0,   0,   0,   0,   0,   0
        };

        private const string Action = "http://www.microsoft.com/BatchActivationService/BatchActivate";

        private static readonly Uri Uri = new Uri("https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx");

        private static readonly XNamespace SoapSchemaNs = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace XmlSchemaInstanceNs = "http://www.w3.org/2001/XMLSchema-instance";
        private static readonly XNamespace XmlSchemaNs = "http://www.w3.org/2001/XMLSchema";
        private static readonly XNamespace BatchActivationServiceNs = "http://www.microsoft.com/BatchActivationService";
        private static readonly XNamespace BatchActivationRequestNs = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";
        private static readonly XNamespace BatchActivationResponseNs = "http://www.microsoft.com/DRM/SL/BatchActivationResponse/1.0";

        public static string CallWebService(int requestType, string installationId, string extendedProductId) {
            XDocument soapRequest = CreateSoapRequest(requestType, installationId, extendedProductId);
            HttpWebRequest webRequest = CreateWebRequest(soapRequest);
            XDocument soapResponse = new XDocument();

            try {
                IAsyncResult asyncResult = webRequest.BeginGetResponse(null, null);
                if (!asyncResult.AsyncWaitHandle.WaitOne(60000, false)) {
                    webRequest.Abort();
                    throw new TimeoutException("Activation service timed out after 60 seconds.");
                }

                // Read data from the response stream.
                using (WebResponse webResponse = webRequest.EndGetResponse(asyncResult))
                using (StreamReader streamReader = new StreamReader(webResponse.GetResponseStream())) {
                    soapResponse = XDocument.Parse(streamReader.ReadToEnd());
                }

                return ParseSoapResponse(soapResponse);

            } catch {
                throw;
            }
        }

        private static XDocument CreateSoapRequest(int requestType, string installationId, string extendedProductId) {
            // Create an activation request.           
            XElement activationRequest = new XElement(BatchActivationRequestNs + "ActivationRequest",
                new XElement(BatchActivationRequestNs + "VersionNumber", "2.0"),
                new XElement(BatchActivationRequestNs + "RequestType", requestType),
                new XElement(BatchActivationRequestNs + "Requests",
                    new XElement(BatchActivationRequestNs + "Request",
                        new XElement(BatchActivationRequestNs + "PID", extendedProductId),
                        requestType == 1 ? new XElement(BatchActivationRequestNs + "IID", installationId) : null)
                )
            );

            // Get the unicode byte array of activationRequest and convert it to Base64.
            byte[] bytes = Encoding.Unicode.GetBytes(activationRequest.ToString());
            string requestXml = Convert.ToBase64String(bytes);

            XDocument soapRequest = new XDocument();

            using (HMACSHA256 hMACSHA = new HMACSHA256(MacKey)) {
                // Convert the HMAC hashed data to Base64.
                string digest = Convert.ToBase64String(hMACSHA.ComputeHash(bytes));

                soapRequest = new XDocument(
                new XDeclaration("1.0", "UTF-8", "no"),
                new XElement(SoapSchemaNs + "Envelope",
                    new XAttribute(XNamespace.Xmlns + "soap", SoapSchemaNs),
                    new XAttribute(XNamespace.Xmlns + "xsi", XmlSchemaInstanceNs),
                    new XAttribute(XNamespace.Xmlns + "xsd", XmlSchemaNs),
                    new XElement(SoapSchemaNs + "Body",
                        new XElement(BatchActivationServiceNs + "BatchActivate",
                            new XElement(BatchActivationServiceNs + "request",
                                new XElement(BatchActivationServiceNs + "Digest", digest),
                                new XElement(BatchActivationServiceNs + "RequestXml", requestXml)
                            )
                        )
                    )
                ));

            }

            return soapRequest;
        }

        private static HttpWebRequest CreateWebRequest(XDocument soapRequest) {
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(Uri);
            webRequest.Accept = "text/xml";
            webRequest.ContentType = "text/xml; charset=\"utf-8\"";
            webRequest.Headers.Add("SOAPAction", Action);
            webRequest.Host = "activation.sls.microsoft.com";
            webRequest.Method = "POST";

            try {
                // Insert SOAP envelope
                using (Stream stream = webRequest.GetRequestStream()) {
                    soapRequest.Save(stream);
                }

                return webRequest;

            } catch {
                throw;
            }
        }

        private static string ParseSoapResponse(XDocument soapResponse) {
            if (soapResponse == null) {
                throw new ArgumentNullException("soapResponse", "The remote server returned an unexpected response.");
            }

            if (!soapResponse.Descendants(BatchActivationServiceNs + "ResponseXml").Any()) {
                throw new Exception("The remote server returned an unexpected response");
            }

            try {
                XDocument responseXml = XDocument.Parse(soapResponse.Descendants(BatchActivationServiceNs + "ResponseXml").First().Value);

                if (responseXml.Descendants(BatchActivationResponseNs + "ErrorCode").Any()) {
                    string errorCode = responseXml.Descendants(BatchActivationResponseNs + "ErrorCode").First().Value;

                    switch (errorCode) {
                        case "0x7F":
                            throw new Exception("The Multiple Activation Key has exceeded its limit");

                        case "0x67":
                            throw new Exception("The product key has been blocked");

                        case "0x68":
                            throw new Exception("Invalid product key");

                        case "0x86":
                            throw new Exception("Invalid key type");

                        case "0x90":
                            throw new Exception("Please check the Installation ID and try again");

                        default:
                            throw new Exception(string.Format("The remote server reported an error ({0})", errorCode));
                    }

                } else if (responseXml.Descendants(BatchActivationResponseNs + "ResponseType").Any()) {
                    string responseType = responseXml.Descendants(BatchActivationResponseNs + "ResponseType").First().Value;

                    switch (responseType) {
                        case "1":
                            string confirmationId = responseXml.Descendants(BatchActivationResponseNs + "CID").First().Value;
                            return confirmationId;

                        case "2":
                            string activationsRemaining = responseXml.Descendants(BatchActivationResponseNs + "ActivationRemaining").First().Value;
                            return activationsRemaining;

                        default:
                            throw new Exception("The remote server returned an unrecognized response");
                    }

                } else {
                    throw new Exception("The remote server returned an unrecognized response");
                }

            } catch {
                throw;
            }
        }
    }
}
#endif

// LibTSforge/Common.cs
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
        public static byte[] ReadExactBytes(this BinaryReader reader, int count)
        {
            if (count < 0 || count > 128 * 1024 * 1024 ||
                count > reader.BaseStream.Length - reader.BaseStream.Position)
                throw new FormatException("Binary field length outside store bounds.");
            byte[] value = reader.ReadBytes(count);
            if (value.Length != count) throw new EndOfStreamException("Incomplete binary field.");
            return value;
        }

        public static void Align(this BinaryReader reader, int to)
        {
            int pos = (int)reader.BaseStream.Position;
            int padding = -pos & (to - 1);
            if (reader.BaseStream.Position + padding > reader.BaseStream.Length)
                throw new FormatException("Binary alignment exceeds stream bounds.");
            reader.BaseStream.Seek(padding, SeekOrigin.Current);
        }

        public static string ReadNullTerminatedString(this BinaryReader reader, int maxLen)
        {
            return Encoding.Unicode.GetString(reader.ReadExactBytes(maxLen)).Split(new char[] { '\0' }, 2)[0];
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
            if (fs.Length > 128 * 1024 * 1024) throw new FormatException("Store exceeds 128 MiB limit.");
            return br.ReadExactBytes((int)(fs.Length - fs.Position));
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


// LibTSforge/SPP/PKeyConfig.cs
namespace LibTSforge.SPP
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Xml;

    public enum PKeyAlgorithm
    {
        PKEY2005,
        PKEY2009
    }

    public class KeyRange
    {
        public int Start;
        public int End;
        public string EulaType;
        public string PartNumber;
        public bool Valid;

        public bool Contains(int n)
        {
            return Start <= n && n <= End;
        }
    }

    public class ProductConfig
    {
        public int GroupId;
        public string Edition;
        public string Description;
        public string Channel;
        public bool Randomized;
        public PKeyAlgorithm Algorithm;
        public List<KeyRange> Ranges;
        public Guid ActivationId;

        private List<KeyRange> GetPkeyRanges()
        {
            if (Ranges.Count == 0)
            {
                throw new ArgumentException("No key ranges.");
            }

            if (Algorithm == PKeyAlgorithm.PKEY2005)
            {
                return Ranges;
            }

            List<KeyRange> FilteredRanges = Ranges.Where(r => !r.EulaType.Contains("WAU")).ToList();

            if (FilteredRanges.Count == 0)
            {
                throw new NotSupportedException("Specified Activation ID is usable only for Windows Anytime Upgrade. Please use a non-WAU Activation ID instead.");
            }

            return FilteredRanges;
        }

        public ProductKey GetRandomKey()
        {
            List<KeyRange> KeyRanges = GetPkeyRanges();
            Random rnd = new Random();

            KeyRange range = KeyRanges[rnd.Next(KeyRanges.Count)];
            int serial = rnd.Next(range.Start, range.End);

            return new ProductKey(serial, 0, false, Algorithm, this, range);
        }
    }

    public class PKeyConfig
    {
        public readonly Dictionary<Guid, ProductConfig> Products = new Dictionary<Guid, ProductConfig>();
        private readonly List<Guid> loadedPkeyConfigs = new List<Guid>();

        public void LoadConfig(Guid actId)
        {
            string pkcData;
            Guid pkcFileId = SLApi.GetPkeyConfigFileId(actId);

            if (loadedPkeyConfigs.Contains(pkcFileId)) return;

            string licConts = SLApi.GetLicenseContents(pkcFileId);

            using (TextReader tr = new StringReader(licConts))
            {
                XmlDocument lic = new XmlDocument();
                lic.Load(tr);

                XmlNamespaceManager nsmgr = new XmlNamespaceManager(lic.NameTable);
                nsmgr.AddNamespace("rg", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
                nsmgr.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
                nsmgr.AddNamespace("tm", "http://www.microsoft.com/DRM/XrML2/TM/v2");

                XmlNode root = lic.DocumentElement;
                XmlNode pkcDataNode = root.SelectSingleNode("/rg:licenseGroup/r:license/r:otherInfo/tm:infoTables/tm:infoList/tm:infoBin[@name=\"pkeyConfigData\"]", nsmgr);
                pkcData = Encoding.UTF8.GetString(Convert.FromBase64String(pkcDataNode.InnerText));
            }

            using (TextReader tr = new StringReader(pkcData))
            {
                XmlDocument lic = new XmlDocument();
                lic.Load(tr);

                XmlNamespaceManager nsmgr = new XmlNamespaceManager(lic.NameTable);
                nsmgr.AddNamespace("p", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
                XmlNodeList configNodes = lic.SelectNodes("//p:ProductKeyConfiguration/p:Configurations/p:Configuration", nsmgr);
                XmlNodeList rangeNodes = lic.SelectNodes("//p:ProductKeyConfiguration/p:KeyRanges/p:KeyRange", nsmgr);
                XmlNodeList pubKeyNodes = lic.SelectNodes("//p:ProductKeyConfiguration/p:PublicKeys/p:PublicKey", nsmgr);

                Dictionary<int, PKeyAlgorithm> algorithms = new Dictionary<int, PKeyAlgorithm>();
                Dictionary<string, List<KeyRange>> ranges = new Dictionary<string, List<KeyRange>>();

                Dictionary<string, PKeyAlgorithm> algoConv = new Dictionary<string, PKeyAlgorithm>
                {
                    { "msft:rm/algorithm/pkey/2005", PKeyAlgorithm.PKEY2005 },
                    { "msft:rm/algorithm/pkey/2009", PKeyAlgorithm.PKEY2009 }
                };

                foreach (XmlNode pubKeyNode in pubKeyNodes)
                {
                    int group = int.Parse(pubKeyNode.SelectSingleNode("./p:GroupId", nsmgr).InnerText);
                    algorithms[group] = algoConv[pubKeyNode.SelectSingleNode("./p:AlgorithmId", nsmgr).InnerText];
                }

                foreach (XmlNode rangeNode in rangeNodes)
                {
                    string refActIdStr = rangeNode.SelectSingleNode("./p:RefActConfigId", nsmgr).InnerText;

                    if (!ranges.ContainsKey(refActIdStr))
                    {
                        ranges[refActIdStr] = new List<KeyRange>();
                    }

                    KeyRange keyRange = new KeyRange
                    {
                        Start = int.Parse(rangeNode.SelectSingleNode("./p:Start", nsmgr).InnerText),
                        End = int.Parse(rangeNode.SelectSingleNode("./p:End", nsmgr).InnerText),
                        EulaType = rangeNode.SelectSingleNode("./p:EulaType", nsmgr).InnerText,
                        PartNumber = rangeNode.SelectSingleNode("./p:PartNumber", nsmgr).InnerText,
                        Valid = rangeNode.SelectSingleNode("./p:IsValid", nsmgr).InnerText.ToLower() == "true"
                    };

                    ranges[refActIdStr].Add(keyRange);
                }

                foreach (XmlNode configNode in configNodes)
                {
                    string refActIdStr = configNode.SelectSingleNode("./p:ActConfigId", nsmgr).InnerText;
                    Guid refActId = new Guid(refActIdStr);
                    int group = int.Parse(configNode.SelectSingleNode("./p:RefGroupId", nsmgr).InnerText);
                    List<KeyRange> keyRanges;
                    ranges.TryGetValue(refActIdStr, out keyRanges);

                    if (keyRanges == null) 
                    {
                        continue;
                    }

                    if (keyRanges.Count > 0 && !Products.ContainsKey(refActId))
                    {
                        PKeyAlgorithm algorithm;
                        algorithms.TryGetValue(group, out algorithm);

                        ProductConfig productConfig = new ProductConfig
                        {
                            GroupId = group,
                            Edition = configNode.SelectSingleNode("./p:EditionId", nsmgr).InnerText,
                            Description = configNode.SelectSingleNode("./p:ProductDescription", nsmgr).InnerText,
                            Channel = configNode.SelectSingleNode("./p:ProductKeyType", nsmgr).InnerText,
                            Randomized = configNode.SelectSingleNode("./p:ProductKeyType", nsmgr).InnerText.ToLower() == "true",
                            Algorithm = algorithm,
                            Ranges = keyRanges,
                            ActivationId = refActId
                        };

                        Products[refActId] = productConfig;
                    }
                }
            }

            loadedPkeyConfigs.Add(pkcFileId);
        }

        public ProductConfig MatchParams(int group, int serial)
        {
            foreach (ProductConfig config in Products.Values)
            {
                if (config.GroupId == group)
                {
                    foreach (KeyRange range in config.Ranges)
                    {
                        if (range.Contains(serial))
                        {
                            return config;
                        }
                    }
                }
            }

            throw new FileNotFoundException("Failed to find product matching supplied product key parameters.");
        }

        public void LoadAllConfigs(Guid appId)
        {
            foreach (Guid actId in SLApi.GetActivationIds(appId))
            {
                try
                {
                    LoadConfig(actId);
                } 
                catch (ArgumentException)
                {

                }
            }
        }
    }
}


// LibTSforge/SPP/ProductKey.cs
namespace LibTSforge.SPP
{
    using System;
    using System.IO;
    using System.Linq;
    using Crypto;
    using PhysicalStore;

    public class ProductKey
    {
        private static readonly string ALPHABET = "BCDFGHJKMPQRTVWXY2346789";

        private readonly ulong klow;
        private readonly ulong khigh;

        public int Group;
        public int Serial;
        public ulong Security;
        public bool Upgrade;
        public PKeyAlgorithm Algorithm;
        public readonly string EulaType;
        public readonly string PartNumber;
        public readonly string Edition;
        public readonly string Channel;
        public readonly Guid ActivationId;

        private string mpc;
        private string pid2;

        public byte[] KeyBytes
        {
            get { return BitConverter.GetBytes(klow).Concat(BitConverter.GetBytes(khigh)).ToArray(); }
        }

        public ProductKey()
        {

        }

        public ProductKey(int serial, ulong security, bool upgrade, PKeyAlgorithm algorithm, ProductConfig config, KeyRange range)
        {
            Group = config.GroupId;
            Serial = serial;
            Security = security;
            Upgrade = upgrade;
            Algorithm = algorithm;
            EulaType = range.EulaType;
            PartNumber = range.PartNumber.Split(':', ';')[0];
            Edition = config.Edition;
            Channel = config.Channel;
            ActivationId = config.ActivationId;

            klow = ((security & 0x3fff) << 50 | ((ulong)serial & 0x3fffffff) << 20 | ((ulong)Group & 0xfffff));
            khigh = ((upgrade ? (ulong)1 : 0) << 49 | ((security >> 14) & 0x7fffffffff));

            uint checksum = Utils.CRC32(KeyBytes) & 0x3ff;

            khigh |= ((ulong)checksum << 39);
        }

        public string GetAlgoUri()
        {
            return "msft:rm/algorithm/pkey/" + (Algorithm == PKeyAlgorithm.PKEY2005 ? "2005" : (Algorithm == PKeyAlgorithm.PKEY2009 ? "2009" : "Unknown"));
        }

        public Guid GetPkeyId()
        {
            VariableBag pkb = new VariableBag(PSVersion.WinModern);
            pkb.Blocks.AddRange(new[]
            {
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyBindingProductKey",
                    ValueAsStr = ToString()
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = "SppPkeyBindingMiscData",
                    Value = new byte[] { }
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyBindingAlgorithm",
                    ValueAsStr = GetAlgoUri()
                }
            });

            return new Guid(CryptoUtils.SHA256Hash(pkb.Serialize()).Take(16).ToArray());
        }

        public string GetMPC()
        {
            if (mpc != null)
            {
                return mpc;
            }

            int build = Environment.OSVersion.Version.Build;

            mpc = build >= 10240 ? "03612" :
                    build >= 9600 ? "06401" :
                    build >= 9200 ? "05426" :
                    "55041";

            // setup.cfg doesn't exist in Windows 8+
            string setupcfg = string.Format(@"{0}\oobe\{1}", Environment.SystemDirectory, "setup.cfg");

            if (!File.Exists(setupcfg) || Edition.Contains(";"))
            {
                return mpc;
            }

            string mpcKey = string.Format("{0}.{1}=", Utils.GetArchitecture(), Edition);
            string localMPC = File.ReadAllLines(setupcfg).FirstOrDefault(line => line.Contains(mpcKey));
            if (localMPC != null)
            {
                mpc = localMPC.Split('=')[1].Trim();
            }

            return mpc;
        }

        public string GetPid2()
        {
            if (pid2 != null)
            {
                return pid2;
            }

            pid2 = "";

            if (Algorithm == PKeyAlgorithm.PKEY2005)
            {
                string mpc = GetMPC();
                string serialHigh;
                int serialLow;
                int lastPart;

                if (EulaType == "OEM")
                {
                    serialHigh = "OEM";
                    serialLow = ((Group / 2) % 100) * 10000 + (Serial / 100000);
                    lastPart = Serial % 100000;
                }
                else
                {
                    serialHigh = (Serial / 1000000).ToString("D3");
                    serialLow = Serial % 1000000;
                    lastPart = ((Group / 2) % 100) * 1000 + new Random().Next(1000);
                }

                int checksum = 0;

                foreach (char c in serialLow.ToString())
                {
                    checksum += int.Parse(c.ToString());
                }
                checksum = 7 - (checksum % 7);

                pid2 = string.Format("{0}-{1}-{2:D6}{3}-{4:D5}", mpc, serialHigh, serialLow, checksum, lastPart);
            }

            return pid2;
        }

        public byte[] GetPid3()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(0xA4);
            writer.Write(0x3);
            writer.WriteFixedString(GetPid2(), 24);
            writer.Write(Group);
            writer.WriteFixedString(PartNumber, 16);
            writer.WritePadding(0x6C);
            byte[] data = writer.GetBytes();
            byte[] crc = BitConverter.GetBytes(~Utils.CRC32(data.Reverse().ToArray())).Reverse().ToArray();
            writer.Write(crc);

            return writer.GetBytes();
        }

        public byte[] GetPid4()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(0x4F8);
            writer.Write(0x4);
            writer.WriteFixedString16(GetExtendedPid(), 0x80);
            writer.WriteFixedString16(ActivationId.ToString(), 0x80);
            writer.WritePadding(0x10);
            writer.WriteFixedString16(Edition, 0x208);
            writer.Write(Upgrade ? (ulong)1 : 0);
            writer.WritePadding(0x50);
            writer.WriteFixedString16(PartNumber, 0x80);
            writer.WriteFixedString16(Channel, 0x80);
            writer.WriteFixedString16(EulaType, 0x80);

            return writer.GetBytes();
        }

        public string GetExtendedPid()
        {
            string mpc = GetMPC();
            int serialHigh = Serial / 1000000;
            int serialLow = Serial % 1000000;
            int licenseType;
            uint lcid = Utils.GetSystemDefaultLCID();
            int build = Environment.OSVersion.Version.Build;
            int dayOfYear = DateTime.Now.DayOfYear;
            int year = DateTime.Now.Year;

            switch (EulaType)
            {
                case "OEM":
                    licenseType = 2;
                    break;

                case "Volume":
                    licenseType = 3;
                    break;

                default:
                    licenseType = 0;
                    break;
            }

            return string.Format(
                "{0}-{1:D5}-{2:D3}-{3:D6}-{4:D2}-{5:D4}-{6:D4}.0000-{7:D3}{8:D4}",
                mpc,
                Group,
                serialHigh,
                serialLow,
                licenseType,
                lcid,
                build,
                dayOfYear,
                year
            );
        }

        public byte[] GetPhoneData(PSVersion version)
        {
            if (version == PSVersion.Win7)
            {
                ulong shortauth = ((ulong)Group << 41) | (Security << 31) | ((ulong)Serial << 1) | (Upgrade ? (ulong)1 : 0);
                return BitConverter.GetBytes(shortauth);
            }

            int serialHigh = Serial / 1000000;
            int serialLow = Serial % 1000000;

            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            string algoId = Algorithm == PKeyAlgorithm.PKEY2005 ? "B8731595-A2F6-430B-A799-FBFFB81A8D73" : "660672EF-7809-4CFD-8D54-41B7FB738988";

            writer.Write(new Guid(algoId).ToByteArray());
            writer.Write(Group);
            writer.Write(serialHigh);
            writer.Write(serialLow);
            writer.Write(Upgrade ? 1 : 0);
            writer.Write(Security);

            return writer.GetBytes();
        }

        public override string ToString()
        {
            string keyStr = "";
            Random rnd = new Random(Group * 1000000000 + Serial);

            if (Algorithm == PKeyAlgorithm.PKEY2005)
            {
                keyStr = "H4X3DH4X3DH4X3DH4X3D";

                for (int i = 0; i < 5; i++)
                {
                    keyStr += ALPHABET[rnd.Next(24)];
                }
            }
            else if (Algorithm == PKeyAlgorithm.PKEY2009)
            {
                int last = 0;
                byte[] bKey = KeyBytes;

                for (int i = 24; i >= 0; i--)
                {
                    int current = 0;

                    for (int j = 14; j >= 0; j--)
                    {
                        current *= 0x100;
                        current += bKey[j];
                        bKey[j] = (byte)(current / 24);
                        current %= 24;
                        last = current;
                    }

                    keyStr = ALPHABET[current] + keyStr;
                }

                keyStr = keyStr.Substring(1, last) + "N" + keyStr.Substring(last + 1, keyStr.Length - last - 1);
            }

            for (int i = 5; i < keyStr.Length; i += 6)
            {
                keyStr = keyStr.Insert(i, "-");
            }

            return keyStr;
        }
    }
}


// LibTSforge/SPP/SLAPI.cs
namespace LibTSforge.SPP
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;

    public static class SLApi
    {
        private enum SLIDTYPE
        {
            SL_ID_APPLICATION,
            SL_ID_PRODUCT_SKU,
            SL_ID_LICENSE_FILE,
            SL_ID_LICENSE,
            SL_ID_PKEY,
            SL_ID_ALL_LICENSES,
            SL_ID_ALL_LICENSE_FILES,
            SL_ID_STORE_TOKEN,
            SL_ID_LAST
        }

        private enum SLDATATYPE
        {
            SL_DATA_NONE,
            SL_DATA_SZ,
            SL_DATA_DWORD,
            SL_DATA_BINARY,
            SL_DATA_MULTI_SZ,
            SL_DATA_SUM
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SL_LICENSING_STATUS
        {
            public Guid SkuId;
            public uint eStatus;
            public uint dwGraceTime;
            public uint dwTotalGraceDays;
            public uint hrReason;
            public ulong qwValidityExpiration;
        }

        public static readonly Guid WINDOWS_APP_ID = new Guid("55c92734-d682-4d71-983e-d6ec3f16059f");

        [DllImport("slc.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void SLOpen(out IntPtr hSLC);

        [DllImport("slc.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void SLClose(IntPtr hSLC);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetWindowsInformationDWORD(string ValueName, ref int Value);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLInstallProofOfPurchase(IntPtr hSLC, string pwszPKeyAlgorithm, string pwszPKeyString, uint cbPKeySpecificData, byte[] pbPKeySpecificData, ref Guid PKeyId);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLUninstallProofOfPurchase(IntPtr hSLC, ref Guid PKeyId);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetPKeyInformation(IntPtr hSLC, ref Guid pPKeyId, string pwszValueName, out SLDATATYPE peDataType, out uint pcbValue, out IntPtr ppbValue);

        [DllImport("slcext.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLActivateProduct(IntPtr hSLC, ref Guid pProductSkuId, byte[] cbAppSpecificData, byte[] pvAppSpecificData, byte[] pActivationInfo, string pwszProxyServer, ushort wProxyPort);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGenerateOfflineInstallationId(IntPtr hSLC, ref Guid pProductSkuId, ref string ppwszInstallationId);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLDepositOfflineConfirmationId(IntPtr hSLC, ref Guid pProductSkuId, string pwszInstallationId, string pwszConfirmationId);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetSLIDList(IntPtr hSLC, SLIDTYPE eQueryIdType, ref Guid pQueryId, SLIDTYPE eReturnIdType, out uint pnReturnIds, out IntPtr ppReturnIds);

        [DllImport("slc.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void SLGetLicensingStatusInformation(IntPtr hSLC, ref Guid pAppID, IntPtr pProductSkuId, string pwszRightName, out uint pnStatusCount, out IntPtr ppLicensingStatus);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetInstalledProductKeyIds(IntPtr hSLC, ref Guid pProductSkuId, out uint pnProductKeyIds, out IntPtr ppProductKeyIds);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLConsumeWindowsRight(uint unknown);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetProductSkuInformation(IntPtr hSLC, ref Guid pProductSkuId, string pwszValueName, out SLDATATYPE peDataType, out uint pcbValue, out IntPtr ppbValue);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLGetLicense(IntPtr hSLC, ref Guid pLicenseFileId, out uint pcbLicenseFile, out IntPtr ppbLicenseFile);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLSetCurrentProductKey(IntPtr hSLC, ref Guid pProductSkuId, ref Guid pProductKeyId);

        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern uint SLFireEvent(IntPtr hSLC, string pwszEventId, ref Guid pApplicationId);

        private class SLContext : IDisposable
        {
            public readonly IntPtr Handle;

            public SLContext()
            {
                SLOpen(out Handle);
            }

            public void Dispose()
            {
                SLClose(Handle);
                GC.SuppressFinalize(this);
            }

            ~SLContext()
            {
                Dispose();
            }
        }

        public static Guid GetDefaultActivationID(Guid appId, bool includeActivated)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                IntPtr pLicStat;

                SLGetLicensingStatusInformation(sl.Handle, ref appId, IntPtr.Zero, null, out count, out pLicStat);

                unsafe
                {
                    SL_LICENSING_STATUS* licensingStatuses = (SL_LICENSING_STATUS*)pLicStat;
                    for (int i = 0; i < count; i++)
                    {
                        SL_LICENSING_STATUS slStatus = licensingStatuses[i];

                        Guid actId = slStatus.SkuId;
                        if (GetInstalledPkeyID(actId) == Guid.Empty) continue;
                        if (IsAddon(actId)) continue;
                        if (!includeActivated && (slStatus.eStatus == 1)) continue;

                        return actId;
                    }
                }

                return Guid.Empty;
            }
        }

        public static string GetInstallationID(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                string installationId = null;
                return SLGenerateOfflineInstallationId(sl.Handle, ref actId, ref installationId) == 0 ? installationId : null;
            }
        }

        public static Guid GetInstalledPkeyID(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                IntPtr pProductKeyIds;

                uint status = SLGetSLIDList(sl.Handle, SLIDTYPE.SL_ID_PRODUCT_SKU, ref actId, SLIDTYPE.SL_ID_PKEY, out count, out pProductKeyIds);

                if (status != 0 || count == 0)
                {
                    return Guid.Empty;
                }

                unsafe { return *(Guid*)pProductKeyIds; }
            }
        }

        public static uint DepositConfirmationID(Guid actId, string installationId, string confirmationId)
        {
            using (SLContext sl = new SLContext())
            {
                return SLDepositOfflineConfirmationId(sl.Handle, ref actId, installationId, confirmationId);
            }
        }

        public static void RefreshLicenseStatus()
        {
            SLConsumeWindowsRight(0);
        }

        public static void RefreshTrustedTime(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                SLDATATYPE type;
                uint count;
                IntPtr ppbValue;

                SLGetProductSkuInformation(sl.Handle, ref actId, "TrustedTime", out type, out count, out ppbValue);
            }
        }

        public static void FireStateChangedEvent(Guid appId)
        {
            using (SLContext sl = new SLContext())
            {
                SLFireEvent(sl.Handle, "msft:rm/event/licensingstatechanged", ref appId);
            }
        }

        public static Guid GetAppId(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                IntPtr pAppIds;

                uint status = SLGetSLIDList(sl.Handle, SLIDTYPE.SL_ID_PRODUCT_SKU, ref actId, SLIDTYPE.SL_ID_APPLICATION, out count, out pAppIds);

                if (status != 0 || count == 0)
                {
                    return Guid.Empty;
                }

                unsafe { return *(Guid*)pAppIds; }
            }
        }

        public static bool IsAddon(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                SLDATATYPE type;
                IntPtr ppbValue;

                uint status = SLGetProductSkuInformation(sl.Handle, ref actId, "DependsOn", out type, out count, out ppbValue);
                return (int)status >= 0 && status != 0xC004F012;
            }
        }

        public static Guid GetLicenseFileId(Guid licId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                IntPtr ppReturnLics;

                uint status = SLGetSLIDList(sl.Handle, SLIDTYPE.SL_ID_LICENSE, ref licId, SLIDTYPE.SL_ID_LICENSE_FILE, out count, out ppReturnLics);

                if (status != 0 || count == 0)
                {
                    return Guid.Empty;
                }

                unsafe { return *(Guid*)ppReturnLics; }
            }
        }

        public static Guid GetPkeyConfigFileId(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                SLDATATYPE type;
                uint len;
                IntPtr ppReturnLics;

                uint status = SLGetProductSkuInformation(sl.Handle, ref actId, "pkeyConfigLicenseId", out type, out len, out ppReturnLics);

                if (status != 0 || len == 0)
                {
                    return Guid.Empty;
                }

                Guid pkcId = new Guid(Marshal.PtrToStringAuto(ppReturnLics));
                return GetLicenseFileId(pkcId);
            }
        }

        public static string GetLicenseContents(Guid fileId)
        {
            if (fileId == Guid.Empty) throw new ArgumentException("License contents could not be retrieved.");

            using (SLContext sl = new SLContext())
            {
                uint dataLen;
                IntPtr dataPtr;

                if (SLGetLicense(sl.Handle, ref fileId, out dataLen, out dataPtr) != 0)
                {
                    return null;
                }

                byte[] data = new byte[dataLen];
                Marshal.Copy(dataPtr, data, 0, (int)dataLen);

                data = data.Skip(Array.IndexOf(data, (byte)'<')).ToArray();
                return Encoding.UTF8.GetString(data);
            }
        }

        public static bool IsPhoneActivatable(Guid actId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                SLDATATYPE type;
                IntPtr ppbValue;

                uint status = SLGetProductSkuInformation(sl.Handle, ref actId, "msft:sl/EUL/PHONE/PUBLIC", out type, out count, out ppbValue);
                return status != 0xC004F012;
            }
        }

        public static string GetPKeyChannel(Guid pkeyId)
        {
            using (SLContext sl = new SLContext())
            {
                SLDATATYPE type;
                uint len;
                IntPtr ppbValue;

                uint status = SLGetPKeyInformation(sl.Handle, ref pkeyId, "Channel", out type, out len, out ppbValue);

                if (status != 0 || len == 0)
                {
                    return null;
                }

                return Marshal.PtrToStringAuto(ppbValue);
            }
        }

        public static string GetMetaStr(Guid actId, string value)
        {
            using (SLContext sl = new SLContext())
            {
                uint len;
                SLDATATYPE type;
                IntPtr ppbValue;

                uint status = SLGetProductSkuInformation(sl.Handle, ref actId, value, out type, out len, out ppbValue);

                if (status != 0 || len == 0 || type != SLDATATYPE.SL_DATA_SZ)
                {
                    return null;
                }

                return Marshal.PtrToStringAuto(ppbValue);
            }
        }

        public static List<Guid> GetActivationIds(Guid appId)
        {
            using (SLContext sl = new SLContext())
            {
                uint count;
                IntPtr pLicStat;

                SLGetLicensingStatusInformation(sl.Handle, ref appId, IntPtr.Zero, null, out count, out pLicStat);

                List<Guid> result = new List<Guid>();

                unsafe
                {
                    SL_LICENSING_STATUS* licensingStatuses = (SL_LICENSING_STATUS*)pLicStat;
                    for (int i = 0; i < count; i++)
                    {
                        result.Add(licensingStatuses[i].SkuId);
                    }
                }

                return result;
            }
        }

        public static uint SetCurrentProductKey(Guid actId, Guid pkeyId)
        {
            using (SLContext sl = new SLContext())
            {
                return SLSetCurrentProductKey(sl.Handle, ref actId, ref pkeyId);
            }
        }

        public static uint InstallProductKey(ProductKey pkey)
        {
            using (SLContext sl = new SLContext())
            {
                Guid pkeyId = Guid.Empty;
                return SLInstallProofOfPurchase(sl.Handle, pkey.GetAlgoUri(), pkey.ToString(), 0, null, ref pkeyId);
            }
        }

        public static void UninstallProductKey(Guid pkeyId)
        {
            using (SLContext sl = new SLContext())
            {
                SLUninstallProofOfPurchase(sl.Handle, ref pkeyId);
            }
        }

        public static void UninstallAllProductKeys(Guid appId)
        {
            foreach (Guid actId in GetActivationIds(appId))
            {
                Guid pkeyId = GetInstalledPkeyID(actId);
                if (pkeyId == Guid.Empty) continue;
                if (IsAddon(actId)) continue;
                UninstallProductKey(pkeyId);
            }
        }
    }
}


// LibTSforge/SPP/SPPUtils.cs
namespace LibTSforge.SPP
{
    using Microsoft.Win32;
    using System;
    using System.IO;
    using System.Linq;
    using System.ServiceProcess;
    using Crypto;
    using PhysicalStore;
    using TokenStore;

    public static class SPPUtils
    {
        public static void KillSPP(PSVersion version)
        {
            ServiceController sc;

            string svcName = version == PSVersion.Vista ? "slsvc" : "sppsvc";

            try
            {
                sc = new ServiceController(svcName);

                if (sc.Status == ServiceControllerStatus.Stopped)
                    return;
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(string.Format("Unable to access {0}: ", svcName) + ex.Message);
            }

            Logger.WriteLine(string.Format("Stopping {0}...", svcName));

            bool stopped = false;

            for (int i = 0; stopped == false && i < 1080; i++)
            {
                try
                {
                    if (sc.Status != ServiceControllerStatus.StopPending)
                        sc.Stop();

                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(500));
                }
                catch (System.ServiceProcess.TimeoutException)
                {
                    continue;
                }
                catch (InvalidOperationException ex)
                {
                    Logger.WriteLine("Warning: Stopping sppsvc failed, retrying. Details: " + ex.Message);
                    System.Threading.Thread.Sleep(500);
                    continue;
                }

                stopped = true;
            }

            if (!stopped)
                throw new System.TimeoutException(string.Format("Failed to stop {0}", svcName));

            Logger.WriteLine(string.Format("{0} stopped successfully.", svcName));

            if (version == PSVersion.Vista && SPSys.IsSpSysRunning())
            {
                Logger.WriteLine("Unloading spsys...");

                int status = SPSys.ControlSpSys(false);

                if (status < 0)
                {
                    throw new IOException("Failed to unload spsys");
                }

                Logger.WriteLine("spsys unloaded successfully.");
            }
        }

        public static void RestartSPP(PSVersion version)
        {
            if (version == PSVersion.Vista)
            {
                ServiceController sc;

                try
                {
                    sc = new ServiceController("slsvc");

                    if (sc.Status == ServiceControllerStatus.Running)
                        return;
                }
                catch (InvalidOperationException ex)
                {
                    throw new InvalidOperationException("Unable to access slsvc: " + ex.Message);
                }

                Logger.WriteLine("Starting slsvc...");

                bool started = false;

                for (int i = 0; started == false && i < 360; i++)
                {
                    try
                    {
                        if (sc.Status != ServiceControllerStatus.StartPending)
                            sc.Start();

                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(500));
                    }
                    catch (System.ServiceProcess.TimeoutException)
                    {
                        continue;
                    }
                    catch (InvalidOperationException ex)
                    {
                        Logger.WriteLine("Warning: Starting slsvc failed, retrying. Details: " + ex.Message);
                        System.Threading.Thread.Sleep(500);
                        continue;
                    }

                    started = true;
                }

                if (!started)
                    throw new System.TimeoutException("Failed to start slsvc");

                Logger.WriteLine("slsvc started successfully.");
            }

            SLApi.RefreshLicenseStatus();
        }

        public static bool DetectCurrentKey()
        {
            SLApi.RefreshLicenseStatus();

            using (RegistryKey wpaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\WPA"))
            {
                foreach (string subKey in wpaKey.GetSubKeyNames())
                {
                    if (subKey.StartsWith("8DEC0AF1"))
                    {
                        return subKey.Contains("P");
                    }
                }
            }

            throw new FileNotFoundException("Failed to autodetect key type, specify physical store key with /prod or /test arguments.");
        }

        public static string GetPSPath(PSVersion version)
        {
            switch (version)
            {
                case PSVersion.Vista:
                case PSVersion.Win7:
                    return Directory.GetFiles(
                        Environment.GetFolderPath(Environment.SpecialFolder.System),
                        "7B296FB0-376B-497e-B012-9C450E1B7327-*.C7483456-A289-439d-8115-601632D005A0")
                    .FirstOrDefault() ?? "";
                default:
                    string psDir = Environment.ExpandEnvironmentVariables(
                        (string)Registry.GetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                            "TokenStore",
                            ""
                        )
                    );
                    string psPath = Path.Combine(psDir, "data.dat");

                    if (string.IsNullOrEmpty(psDir) || !File.Exists(psPath))
                    {
                        string[] psDirs =
                        {
                            @"spp\store",
                            @"spp\store\2.0",
                            @"spp\store_test",
                            @"spp\store_test\2.0"
                        };

                        foreach (string dir in psDirs)
                        {
                            psPath = Path.Combine(
                                Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                                    dir
                                ),
                                "data.dat"
                            );

                            if (File.Exists(psPath)) return psPath;
                        }
                    } 
                    else
                    {
                        return psPath;
                    }

                    throw new FileNotFoundException("Failed to locate physical store.");
            }
        }

        public static string GetTokensPath(PSVersion version)
        {
            switch (version)
            {
                case PSVersion.Vista:
                    return Path.Combine(
                        Environment.ExpandEnvironmentVariables("%WINDIR%"),
                        @"ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareLicensing\tokens.dat"
                    );
                case PSVersion.Win7:
                    return Path.Combine(
                        Environment.ExpandEnvironmentVariables("%WINDIR%"),
                        @"ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform\tokens.dat"
                    );
                default:
                    string tokDir = Environment.ExpandEnvironmentVariables(
                        (string)Registry.GetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                            "TokenStore",
                            ""
                        )
                    );
                    string tokPath = Path.Combine(tokDir, "tokens.dat");

                    if (string.IsNullOrEmpty(tokDir) || !File.Exists(tokPath))
                    {
                        string[] tokDirs =
                        {
                            @"spp\store",
                            @"spp\store\2.0",
                            @"spp\store_test",
                            @"spp\store_test\2.0"
                        };

                        foreach (string dir in tokDirs)
                        {
                            tokPath = Path.Combine(
                                Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                                    dir
                                ),
                                "tokens.dat"
                            );

                            if (File.Exists(tokPath)) return tokPath;
                        }
                    }
                    else
                    {
                        return tokPath;
                    }

                    throw new FileNotFoundException("Failed to locate token store.");
            }
        }

        public static IPhysicalStore GetStore(PSVersion version, bool production)
        {
            string psPath = GetPSPath(version);

            switch (version)
            {
                case PSVersion.Vista:
                    return new PhysicalStoreVista(psPath, production);
                case PSVersion.Win7:
                    return new PhysicalStoreWin7(psPath, production);
                default:
                    return new PhysicalStoreModern(psPath, production, version);
            }
        }

        public static ITokenStore GetTokenStore(PSVersion version)
        {
            string tokPath = GetTokensPath(version);

            return new TokenStoreModern(tokPath);
        }

        public static void DumpStore(PSVersion version, bool production, string filePath, string encrFilePath)
        {
            bool manageSpp = false;

            if (encrFilePath == null)
            {
                encrFilePath = GetPSPath(version);
                manageSpp = true;
                KillSPP(version);
            }

            if (string.IsNullOrEmpty(encrFilePath) || !File.Exists(encrFilePath))
            {
                throw new FileNotFoundException("Store does not exist at expected path '" + encrFilePath + "'.");
            }

            try
            {
                using (FileStream fs = File.Open(encrFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] encrData = fs.ReadAllBytes();
                    File.WriteAllBytes(filePath, PhysStoreCrypto.DecryptPhysicalStore(encrData, production, version));
                }
                Logger.WriteLine("Store dumped successfully to '" + filePath + "'.");
            }
            finally
            {
                if (manageSpp)
                {
                    RestartSPP(version);
                }
            }
        }

        public static void LoadStore(PSVersion version, bool production, string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                throw new FileNotFoundException("Store file '" + filePath + "' does not exist.");
            }

            KillSPP(version);

            using (IPhysicalStore store = GetStore(version, production))
            {
                store.WriteRaw(File.ReadAllBytes(filePath));
            }

            RestartSPP(version);

            Logger.WriteLine("Loaded store file successfully.");
        }
    }
}


// LibTSforge/SPP/SPSys.cs
namespace LibTSforge.SPP
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Runtime.InteropServices;

    public class SPSys
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        private static SafeFileHandle CreateFileSafe(string device)
        {
            return new SafeFileHandle(CreateFile(device, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero), true);
        }

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool DeviceIoControl([In] SafeFileHandle hDevice, [In] uint dwIoControlCode, [In] IntPtr lpInBuffer, [In] int nInBufferSize, [Out] IntPtr lpOutBuffer, [In] int nOutBufferSize, out int lpBytesReturned, [In] IntPtr lpOverlapped);

        public static bool IsSpSysRunning()
        {
            SafeFileHandle file = CreateFileSafe(@"\\.\SpDevice");
            IntPtr buffer = Marshal.AllocHGlobal(1);
            int bytesReturned;
            DeviceIoControl(file, 0x80006008, IntPtr.Zero, 0, buffer, 1, out bytesReturned, IntPtr.Zero);
            bool running = Marshal.ReadByte(buffer) != 0;
            Marshal.FreeHGlobal(buffer);
            file.Close();
            return running;
        }

        public static int ControlSpSys(bool start)
        {
            SafeFileHandle file = CreateFileSafe(@"\\.\SpDevice");
            IntPtr buffer = Marshal.AllocHGlobal(4);
            int bytesReturned;
            DeviceIoControl(file, start ? 0x8000a000 : 0x8000a004, IntPtr.Zero, 0, buffer, 4, out bytesReturned, IntPtr.Zero);
            int result = Marshal.ReadInt32(buffer);
            Marshal.FreeHGlobal(buffer);
            file.Close();
            return result;
        }
    }
}


// LibTSforge/Crypto/CryptoUtils.cs
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


// LibTSforge/Crypto/Keys.cs
namespace LibTSforge.Crypto
{
    public static class Keys
    {
        public static readonly byte[] PRODUCTION = {
            0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x29, 0x87, 0xBA, 0x3F, 0x52, 0x90, 0x57, 0xD8, 0x12, 0x26, 0x6B, 0x38,
            0xB2, 0x3B, 0xF9, 0x67, 0x08, 0x4F, 0xDD, 0x8B, 0xF5, 0xE3, 0x11, 0xB8, 0x61, 0x3A, 0x33, 0x42,
            0x51, 0x65, 0x05, 0x86, 0x1E, 0x00, 0x41, 0xDE, 0xC5, 0xDD, 0x44, 0x60, 0x56, 0x3D, 0x14, 0x39,
            0xB7, 0x43, 0x65, 0xE9, 0xF7, 0x2B, 0xA5, 0xF0, 0xA3, 0x65, 0x68, 0xE9, 0xE4, 0x8B, 0x5C, 0x03,
            0x2D, 0x36, 0xFE, 0x28, 0x4C, 0xD1, 0x3C, 0x3D, 0xC1, 0x90, 0x75, 0xF9, 0x6E, 0x02, 0xE0, 0x58,
            0x97, 0x6A, 0xCA, 0x80, 0x02, 0x42, 0x3F, 0x6C, 0x15, 0x85, 0x4D, 0x83, 0x23, 0x6A, 0x95, 0x9E,
            0x38, 0x52, 0x59, 0x38, 0x6A, 0x99, 0xF0, 0xB5, 0xCD, 0x53, 0x7E, 0x08, 0x7C, 0xB5, 0x51, 0xD3,
            0x8F, 0xA3, 0x0D, 0xA0, 0xFA, 0x8D, 0x87, 0x3C, 0xFC, 0x59, 0x21, 0xD8, 0x2E, 0xD9, 0x97, 0x8B,
            0x40, 0x60, 0xB1, 0xD7, 0x2B, 0x0A, 0x6E, 0x60, 0xB5, 0x50, 0xCC, 0x3C, 0xB1, 0x57, 0xE4, 0xB7,
            0xDC, 0x5A, 0x4D, 0xE1, 0x5C, 0xE0, 0x94, 0x4C, 0x5E, 0x28, 0xFF, 0xFA, 0x80, 0x6A, 0x13, 0x53,
            0x52, 0xDB, 0xF3, 0x04, 0x92, 0x43, 0x38, 0xB9, 0x1B, 0xD9, 0x85, 0x54, 0x7B, 0x14, 0xC7, 0x89,
            0x16, 0x8A, 0x4B, 0x82, 0xA1, 0x08, 0x02, 0x99, 0x23, 0x48, 0xDD, 0x75, 0x9C, 0xC8, 0xC1, 0xCE,
            0xB0, 0xD7, 0x1B, 0xD8, 0xFB, 0x2D, 0xA7, 0x2E, 0x47, 0xA7, 0x18, 0x4B, 0xF6, 0x29, 0x69, 0x44,
            0x30, 0x33, 0xBA, 0xA7, 0x1F, 0xCE, 0x96, 0x9E, 0x40, 0xE1, 0x43, 0xF0, 0xE0, 0x0D, 0x0A, 0x32,
            0xB4, 0xEE, 0xA1, 0xC3, 0x5E, 0x9B, 0xC7, 0x7F, 0xF5, 0x9D, 0xD8, 0xF2, 0x0F, 0xD9, 0x8F, 0xAD,
            0x75, 0x0A, 0x00, 0xD5, 0x25, 0x43, 0xF7, 0xAE, 0x51, 0x7F, 0xB7, 0xDE, 0xB7, 0xAD, 0xFB, 0xCE,
            0x83, 0xE1, 0x81, 0xFF, 0xDD, 0xA2, 0x77, 0xFE, 0xEB, 0x27, 0x1F, 0x10, 0xFA, 0x82, 0x37, 0xF4,
            0x7E, 0xCC, 0xE2, 0xA1, 0x58, 0xC8, 0xAF, 0x1D, 0x1A, 0x81, 0x31, 0x6E, 0xF4, 0x8B, 0x63, 0x34,
            0xF3, 0x05, 0x0F, 0xE1, 0xCC, 0x15, 0xDC, 0xA4, 0x28, 0x7A, 0x9E, 0xEB, 0x62, 0xD8, 0xD8, 0x8C,
            0x85, 0xD7, 0x07, 0x87, 0x90, 0x2F, 0xF7, 0x1C, 0x56, 0x85, 0x2F, 0xEF, 0x32, 0x37, 0x07, 0xAB,
            0xB0, 0xE6, 0xB5, 0x02, 0x19, 0x35, 0xAF, 0xDB, 0xD4, 0xA2, 0x9C, 0x36, 0x80, 0xC6, 0xDC, 0x82,
            0x08, 0xE0, 0xC0, 0x5F, 0x3C, 0x59, 0xAA, 0x4E, 0x26, 0x03, 0x29, 0xB3, 0x62, 0x58, 0x41, 0x59,
            0x3A, 0x37, 0x43, 0x35, 0xE3, 0x9F, 0x34, 0xE2, 0xA1, 0x04, 0x97, 0x12, 0x9D, 0x8C, 0xAD, 0xF7,
            0xFB, 0x8C, 0xA1, 0xA2, 0xE9, 0xE4, 0xEF, 0xD9, 0xC5, 0xE5, 0xDF, 0x0E, 0xBF, 0x4A, 0xE0, 0x7A,
            0x1E, 0x10, 0x50, 0x58, 0x63, 0x51, 0xE1, 0xD4, 0xFE, 0x57, 0xB0, 0x9E, 0xD7, 0xDA, 0x8C, 0xED,
            0x7D, 0x82, 0xAC, 0x2F, 0x25, 0x58, 0x0A, 0x58, 0xE6, 0xA4, 0xF4, 0x57, 0x4B, 0xA4, 0x1B, 0x65,
            0xB9, 0x4A, 0x87, 0x46, 0xEB, 0x8C, 0x0F, 0x9A, 0x48, 0x90, 0xF9, 0x9F, 0x76, 0x69, 0x03, 0x72,
            0x77, 0xEC, 0xC1, 0x42, 0x4C, 0x87, 0xDB, 0x0B, 0x3C, 0xD4, 0x74, 0xEF, 0xE5, 0x34, 0xE0, 0x32,
            0x45, 0xB0, 0xF8, 0xAB, 0xD5, 0x26, 0x21, 0xD7, 0xD2, 0x98, 0x54, 0x8F, 0x64, 0x88, 0x20, 0x2B,
            0x14, 0xE3, 0x82, 0xD5, 0x2A, 0x4B, 0x8F, 0x4E, 0x35, 0x20, 0x82, 0x7E, 0x1B, 0xFE, 0xFA, 0x2C,
            0x79, 0x6C, 0x6E, 0x66, 0x94, 0xBB, 0x0A, 0xEB, 0xBA, 0xD9, 0x70, 0x61, 0xE9, 0x47, 0xB5, 0x82,
            0xFC, 0x18, 0x3C, 0x66, 0x3A, 0x09, 0x2E, 0x1F, 0x61, 0x74, 0xCA, 0xCB, 0xF6, 0x7A, 0x52, 0x37,
            0x1D, 0xAC, 0x8D, 0x63, 0x69, 0x84, 0x8E, 0xC7, 0x70, 0x59, 0xDD, 0x2D, 0x91, 0x1E, 0xF7, 0xB1,
            0x56, 0xED, 0x7A, 0x06, 0x9D, 0x5B, 0x33, 0x15, 0xDD, 0x31, 0xD0, 0xE6, 0x16, 0x07, 0x9B, 0xA5,
            0x94, 0x06, 0x7D, 0xC1, 0xE9, 0xD6, 0xC8, 0xAF, 0xB4, 0x1E, 0x2D, 0x88, 0x06, 0xA7, 0x63, 0xB8,
            0xCF, 0xC8, 0xA2, 0x6E, 0x84, 0xB3, 0x8D, 0xE5, 0x47, 0xE6, 0x13, 0x63, 0x8E, 0xD1, 0x7F, 0xD4,
            0x81, 0x44, 0x38, 0xBF
        };

        public static readonly byte[] TEST = {
            0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x0F, 0xBE, 0x77, 0xB8, 0xDD, 0x54, 0x36, 0xDD, 0x67, 0xD4, 0x17, 0x66,
            0xC4, 0x13, 0xD1, 0x3F, 0x1E, 0x16, 0x0C, 0x16, 0x35, 0xAB, 0x6D, 0x3D, 0x34, 0x51, 0xED, 0x3F,
            0x57, 0x14, 0xB6, 0xB7, 0x08, 0xE9, 0xD9, 0x7A, 0x80, 0xB3, 0x5F, 0x9B, 0x3A, 0xFD, 0x9E, 0x37,
            0x3A, 0x53, 0x72, 0x67, 0x92, 0x60, 0xC3, 0xEF, 0xB5, 0x8E, 0x1E, 0xCF, 0x9D, 0x9C, 0xD3, 0x90,
            0xE5, 0xDD, 0xF4, 0xDB, 0xF3, 0xD6, 0x65, 0xB3, 0xC1, 0xBD, 0x69, 0xE1, 0x76, 0x95, 0xD9, 0x37,
            0xB8, 0x5E, 0xCA, 0x3D, 0x98, 0xFC, 0x50, 0x5C, 0x98, 0xAE, 0xE3, 0x7C, 0x4C, 0x27, 0xC3, 0xD0,
            0xCE, 0x78, 0x06, 0x51, 0x68, 0x23, 0xE6, 0x70, 0xF8, 0x7C, 0xAE, 0x36, 0xBE, 0x41, 0x57, 0xE2,
            0xC3, 0x2D, 0xAF, 0x21, 0xB1, 0xB3, 0x15, 0x81, 0x19, 0x26, 0x6B, 0x10, 0xB3, 0xE9, 0xD1, 0x45,
            0x21, 0x77, 0x9C, 0xF6, 0xE1, 0xDD, 0xB6, 0x78, 0x9D, 0x1D, 0x32, 0x61, 0xBC, 0x2B, 0xDB, 0x86,
            0xFB, 0x07, 0x24, 0x10, 0x19, 0x4F, 0x09, 0x6D, 0x03, 0x90, 0xD4, 0x5E, 0x30, 0x85, 0xC5, 0x58,
            0x7E, 0x5D, 0xAE, 0x9F, 0x64, 0x93, 0x04, 0x82, 0x09, 0x0E, 0x1C, 0x66, 0xA8, 0x95, 0x91, 0x51,
            0xB2, 0xED, 0x9A, 0x75, 0x04, 0x87, 0x50, 0xAC, 0xCC, 0x20, 0x06, 0x45, 0xB9, 0x7B, 0x42, 0x53,
            0x9A, 0xD1, 0x29, 0xFC, 0xEF, 0xB9, 0x47, 0x16, 0x75, 0x69, 0x05, 0x87, 0x2B, 0xCB, 0x54, 0x9C,
            0x21, 0x2D, 0x50, 0x8E, 0x12, 0xDE, 0xD3, 0x6B, 0xEC, 0x92, 0xA1, 0xB1, 0xE9, 0x4B, 0xBF, 0x6B,
            0x9A, 0x38, 0xC7, 0x13, 0xFA, 0x78, 0xA1, 0x3C, 0x1E, 0xBB, 0x38, 0x31, 0xBB, 0x0C, 0x9F, 0x70,
            0x1A, 0x31, 0x00, 0xD7, 0x5A, 0xA5, 0x84, 0x24, 0x89, 0x80, 0xF5, 0x88, 0xC2, 0x31, 0x18, 0xDC,
            0x53, 0x05, 0x5D, 0xFA, 0x81, 0xDC, 0xE1, 0xCE, 0xA4, 0xAA, 0xBA, 0x07, 0xDA, 0x28, 0x4F, 0x64,
            0x0E, 0x84, 0x9B, 0x06, 0xDE, 0xC8, 0x78, 0x66, 0x2F, 0x17, 0x25, 0xA8, 0x9C, 0x99, 0xFC, 0xBC,
            0x7D, 0x01, 0x42, 0xD7, 0x35, 0xBF, 0x19, 0xF6, 0x3F, 0x20, 0xD9, 0x98, 0x9B, 0x5D, 0xDD, 0x39,
            0xBE, 0x81, 0x00, 0x0B, 0xDE, 0x6F, 0x14, 0xCA, 0x7E, 0xF8, 0xC0, 0x26, 0xA8, 0x1D, 0xD1, 0x16,
            0x88, 0x64, 0x87, 0x36, 0x45, 0x37, 0x50, 0xDA, 0x6C, 0xEB, 0x85, 0xB5, 0x43, 0x29, 0x88, 0x6F,
            0x2F, 0xFE, 0x8D, 0x12, 0x8B, 0x72, 0xB7, 0x5A, 0xCB, 0x66, 0xC2, 0x2E, 0x1D, 0x7D, 0x42, 0xA6,
            0xF4, 0xFE, 0x26, 0x5D, 0x54, 0x9E, 0x77, 0x1D, 0x97, 0xC2, 0xF3, 0xFD, 0x60, 0xB3, 0x22, 0x88,
            0xCA, 0x27, 0x99, 0xDF, 0xC8, 0xB1, 0xD7, 0xC6, 0x54, 0xA6, 0x50, 0xB9, 0x54, 0xF5, 0xDE, 0xFE,
            0xE1, 0x81, 0xA2, 0xBE, 0x81, 0x9F, 0x48, 0xFF, 0x2F, 0xB8, 0xA4, 0xB3, 0x17, 0xD8, 0xC1, 0xB9,
            0x5D, 0x21, 0x3D, 0xA2, 0xED, 0x1C, 0x96, 0x66, 0xEE, 0x1F, 0x47, 0xCF, 0x62, 0xFA, 0xD6, 0xC1,
            0x87, 0x5B, 0xC4, 0xE5, 0xD9, 0x08, 0x38, 0x22, 0xFA, 0x21, 0xBD, 0xF2, 0x88, 0xDA, 0xE2, 0x24,
            0x25, 0x1F, 0xF1, 0x0B, 0x2D, 0xAE, 0x04, 0xBE, 0xA6, 0x7F, 0x75, 0x8C, 0xD9, 0x97, 0xE1, 0xCA,
            0x35, 0xB9, 0xFC, 0x6F, 0x01, 0x68, 0x11, 0xD3, 0x68, 0x32, 0xD0, 0xC1, 0x69, 0xA3, 0xCF, 0x9B,
            0x10, 0xE4, 0x69, 0xA7, 0xCF, 0xE1, 0xFE, 0x2A, 0x07, 0x9E, 0xC1, 0x37, 0x84, 0x68, 0xE5, 0xC5,
            0xAB, 0x25, 0xEC, 0x7D, 0x7D, 0x74, 0x6A, 0xD1, 0xD5, 0x4D, 0xD7, 0xE1, 0x7D, 0xDE, 0x30, 0x4B,
            0xE6, 0x5D, 0xCD, 0x91, 0x59, 0xF6, 0x80, 0xFD, 0xC6, 0x3C, 0xDD, 0x94, 0x7F, 0x15, 0x9D, 0xEF,
            0x2F, 0x00, 0x62, 0xD7, 0xDA, 0xB9, 0xB3, 0xD9, 0x8D, 0xE8, 0xD7, 0x3C, 0x96, 0x45, 0x5D, 0x1E,
            0x50, 0xFB, 0xAA, 0x43, 0xD3, 0x47, 0x77, 0x81, 0xE9, 0x67, 0xE4, 0xFE, 0xDF, 0x42, 0x79, 0xCB,
            0xA7, 0xAD, 0x5D, 0x48, 0xF5, 0xB7, 0x74, 0x96, 0x12, 0x23, 0x06, 0x70, 0x42, 0x68, 0x7A, 0x44,
            0xFC, 0xA0, 0x31, 0x7F, 0x68, 0xCA, 0xA2, 0x14, 0x5D, 0xA3, 0xCF, 0x42, 0x23, 0xAB, 0x47, 0xF6,
            0xB2, 0xFC, 0x6D, 0xF1
        };
    }
}


// LibTSforge/Crypto/PhysStoreCrypto.cs
namespace LibTSforge.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;

    public static class PhysStoreCrypto
    {
        public static byte[] DecryptPhysicalStore(byte[] data, bool production, PSVersion version)
        {
            byte[] rsaKey = production ? Keys.PRODUCTION : Keys.TEST;
            BinaryReader br = new BinaryReader(new MemoryStream(data));
            br.BaseStream.Seek(0x10, SeekOrigin.Begin);
            byte[] aesKeySig = br.ReadExactBytes(0x80);
            byte[] encAesKey = br.ReadExactBytes(0x80);

            if (!CryptoUtils.RSAVerifySignature(rsaKey, encAesKey, aesKeySig))
            {
                throw new Exception("Failed to decrypt physical store.");
            }

            byte[] aesKey = CryptoUtils.RSADecrypt(rsaKey, encAesKey);
            byte[] decData = CryptoUtils.AESDecrypt(br.ReadExactBytes((int)br.BaseStream.Length - 0x110), aesKey);
            byte[] hmacKey = decData.Take(0x10).ToArray(); // SHA-1 salt on Vista
            byte[] hmacSig = decData.Skip(0x10).Take(0x14).ToArray(); // SHA-1 hash on Vista
            byte[] psData = decData.Skip(0x28).ToArray();

            if (version != PSVersion.Vista)
            {
                if (!CryptoUtils.HMACVerify(hmacKey, psData, hmacSig))
                {
                    throw new InvalidDataException("Failed to verify HMAC. Physical store is corrupt.");
                }
            }
            else
            {
                if (!CryptoUtils.SaltSHAVerify(hmacKey, psData, hmacSig))
                {
                    throw new InvalidDataException("Failed to verify checksum. Physical store is corrupt.");
                }
            }

            return psData;
        }

        public static byte[] EncryptPhysicalStore(byte[] data, bool production, PSVersion version)
        {
            Dictionary<PSVersion, int> versionTable = new Dictionary<PSVersion, int>
            {
                {PSVersion.Vista, 2},
                {PSVersion.Win7, 5},
                {PSVersion.Win8, 1},
                {PSVersion.WinBlue, 2},
                {PSVersion.WinModern, 3}
            };

            byte[] rsaKey = production ? Keys.PRODUCTION : Keys.TEST;

            byte[] aesKey = Encoding.UTF8.GetBytes("massgrave.dev :3");
            byte[] hmacKey = CryptoUtils.GenerateRandomKey(0x10);

            byte[] encAesKey = CryptoUtils.RSAEncrypt(rsaKey, aesKey);
            byte[] aesKeySig = CryptoUtils.RSASign(rsaKey, encAesKey);
            byte[] hmacSig = version != PSVersion.Vista ? CryptoUtils.HMACSign(hmacKey, data) : CryptoUtils.SaltSHASum(hmacKey, data);

            byte[] decData = { };
            decData = decData.Concat(hmacKey).Concat(hmacSig).Concat(BitConverter.GetBytes(0)).Concat(data).ToArray();
            byte[] encData = CryptoUtils.AESEncrypt(decData, aesKey);

            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(versionTable[version]);
            bw.Write(Encoding.UTF8.GetBytes("UNTRUSTSTORE"));
            bw.Write(aesKeySig);
            bw.Write(encAesKey);
            bw.Write(encData);

            return bw.GetBytes();
        }
    }
}


// LibTSforge/Modifiers/GenPKeyInstall.cs
namespace LibTSforge.Modifiers
{
    using System;
    using System.IO;
    using Microsoft.Win32;
    using PhysicalStore;
    using SPP;
    using TokenStore;

    public static class GenPKeyInstall
    {
        private static void WritePkey2005RegistryValues(PSVersion version, ProductKey pkey)
        {
            Logger.WriteLine("Writing registry data for Windows product key...");
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductId", pkey.GetPid2());
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DigitalProductId", pkey.GetPid3());
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DigitalProductId4", pkey.GetPid4());

            if (Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration", "ProductId", null) != null)
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration", "ProductId", pkey.GetPid2());
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration", "DigitalProductId", pkey.GetPid3());
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Registration", "DigitalProductId4", pkey.GetPid4());
            }

            if (pkey.Channel == "Volume:CSVLK" && version != PSVersion.Win7)
            {
                Registry.SetValue(@"HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform", "KmsHostConfig", 1);
            }
        }

        public static void InstallGenPKey(PSVersion version, bool production, Guid actId)
        {
            if (version == PSVersion.Vista) throw new NotSupportedException("This feature is not supported on Windows Vista/Server 2008.");
            if (actId == Guid.Empty) throw new ArgumentException("Activation ID must be specified for generated product key install.");

            PKeyConfig pkc = new PKeyConfig();
            
            try
            {
                pkc.LoadConfig(actId);
            }
            catch (ArgumentException)
            {
                pkc.LoadAllConfigs(SLApi.GetAppId(actId));
            }

            ProductConfig config;
            pkc.Products.TryGetValue(actId, out config);

            if (config == null) throw new ArgumentException("Activation ID " + actId + " not found in PKeyConfig.");

            ProductKey pkey = config.GetRandomKey();

            Guid instPkeyId = SLApi.GetInstalledPkeyID(actId);
            if (instPkeyId != Guid.Empty) SLApi.UninstallProductKey(instPkeyId);

            if (pkey.Algorithm == PKeyAlgorithm.PKEY2009)
            {
                uint status = SLApi.InstallProductKey(pkey);
                Logger.WriteLine(string.Format("Installing generated product key {0} status {1:X}", pkey, status));

                if ((int)status < 0)
                {
                    throw new ApplicationException("Failed to install generated product key.");
                }

                Logger.WriteLine("Successfully deposited generated product key.");
                return;
            }

            Logger.WriteLine("Key range is PKEY2005, creating fake key data...");

            if (pkey.Channel == "Volume:GVLK" && version == PSVersion.Win7) throw new NotSupportedException("Fake GVLK generation is not supported on Windows 7.");

            VariableBag pkb = new VariableBag(version);
            pkb.Blocks.AddRange(new[]
            {
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyBindingProductKey",
                    ValueAsStr = pkey.ToString()
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyBindingMPC",
                    ValueAsStr = pkey.GetMPC()
                },
                new CRCBlockModern {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = "SppPkeyBindingPid2",
                    ValueAsStr = pkey.GetPid2()
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = "SppPkeyBindingPid3",
                    Value = pkey.GetPid3()
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = "SppPkeyBindingPid4",
                    Value = pkey.GetPid4()
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyChannelId",
                    ValueAsStr = pkey.Channel
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.STRING,
                    KeyAsStr = "SppPkeyBindingEditionId",
                    ValueAsStr = pkey.Edition
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = (version == PSVersion.Win7) ? "SppPkeyShortAuthenticator" : "SppPkeyPhoneActivationData",
                    Value = pkey.GetPhoneData(version)
                },
                new CRCBlockModern
                {
                    DataType = CRCBlockType.BINARY,
                    KeyAsStr = "SppPkeyBindingMiscData",
                    Value = new byte[] { }
                }
            });

            Guid appId = SLApi.GetAppId(actId);
            string pkeyId = pkey.GetPkeyId().ToString();
            bool isAddon = SLApi.IsAddon(actId);
            string currEdition = SLApi.GetMetaStr(actId, "Family");

            if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
            {
                SLApi.UninstallAllProductKeys(appId);
            }

            SPPUtils.KillSPP(version);

            using (StoreWriteBatch batch = new StoreWriteBatch())
            {
            using (IPhysicalStore ps = SPPUtils.GetStore(version, production))
            {
                using (ITokenStore tks = SPPUtils.GetTokenStore(version))
                {
                    Logger.WriteLine("Writing to physical store and token store...");

                    string suffix = (version == PSVersion.Win8 || version == PSVersion.WinBlue || version == PSVersion.WinModern) ? "_--" : "";
                    string metSuffix = suffix + "_met";

                    if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
                    {
                        string edTokName = "msft:spp/token/windows/productkeyid/" + currEdition;

                        TokenMeta edToken = tks.GetMetaEntry(edTokName);
                        edToken.Data["windowsComponentEditionPkeyId"] = pkeyId;
                        edToken.Data["windowsComponentEditionSkuId"] = actId.ToString();
                        tks.SetEntry(edTokName, "xml", edToken.Serialize());

                        WritePkey2005RegistryValues(version, pkey);
                    }

                    string uriMapName = "msft:spp/token/PKeyIdUriMapper" + metSuffix;
                    TokenMeta uriMap = tks.GetMetaEntry(uriMapName);
                    uriMap.Data[pkeyId] = pkey.GetAlgoUri();
                    tks.SetEntry(uriMapName, "xml", uriMap.Serialize());

                    string skuMetaName = actId + metSuffix;
                    TokenMeta skuMeta = tks.GetMetaEntry(skuMetaName);

                    foreach (string k in skuMeta.Data.Keys)
                    {
                        if (k.StartsWith("pkeyId_"))
                        {
                            skuMeta.Data.Remove(k);
                            break;
                        }
                    }

                    skuMeta.Data["pkeyId"] = pkeyId;
                    skuMeta.Data["pkeyIdList"] = pkeyId;
                    tks.SetEntry(skuMetaName, "xml", skuMeta.Serialize());

                    string psKey = string.Format("SPPSVC\\{0}\\{1}", appId, actId);
                    ps.DeleteBlock(psKey, pkeyId);
                    ps.AddBlock(new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = (version == PSVersion.WinModern) ? (uint)0x402 : 0x2,
                        KeyAsStr = psKey,
                        ValueAsStr = pkeyId,
                        Data = pkb.Serialize()
                    });

                    string cachePath = SPPUtils.GetTokensPath(version).Replace("tokens.dat", @"cache\cache.dat");
                    if (File.Exists(cachePath)) File.Delete(cachePath);
                    tks.Commit();
                }
                ps.Commit();
            }
                batch.Commit();
            }

            SLApi.RefreshTrustedTime(actId);
            Logger.WriteLine("Successfully deposited fake product key.");
        }
    }
}


// LibTSforge/Modifiers/GracePeriodReset.cs
namespace LibTSforge.Modifiers
{
    using System.Collections.Generic;
    using System.Linq;
    using PhysicalStore;
    using SPP;

    public static class GracePeriodReset
    {
        public static void Reset(PSVersion version, bool production)
        {
            SPPUtils.KillSPP(version);
            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                string value = "msft:sl/timer";
                List<PSBlock> blocks = store.FindBlocks(value).ToList();

                foreach (PSBlock block in blocks)
                {
                    store.DeleteBlock(block.KeyAsStr, block.ValueAsStr);
                }
                store.Commit();
            }

            SPPUtils.RestartSPP(version);
            Logger.WriteLine("Successfully reset all grace and evaluation period timers.");
        }
    }
}


// LibTSforge/Modifiers/KeyChangeLockDelete.cs
namespace LibTSforge.Modifiers
{
    using System.Collections.Generic;
    using System.Linq;
    using PhysicalStore;
    using SPP;
    using System;

    public static class KeyChangeLockDelete
    {
        public static void Delete(PSVersion version, bool production)
        {
            if (version == PSVersion.Vista) throw new NotSupportedException("This feature is not supported on Windows Vista/Server 2008.");

            SPPUtils.KillSPP(version);
            Logger.WriteLine("Writing TrustedStore data...");
            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                List<string> values = new List<string>
                {
                    "msft:spp/timebased/AB",
                    "msft:spp/timebased/CD"
                };
                List<PSBlock> blocks = new List<PSBlock>();
                foreach (string value in values)
                {
                    blocks.AddRange(store.FindBlocks(value).ToList());
                }
                foreach (PSBlock block in blocks)
                {
                    store.DeleteBlock(block.KeyAsStr, block.ValueAsStr);
                }
                store.Commit();
            }
            Logger.WriteLine("Successfully removed the key change lock.");
        }
    }
}


// LibTSforge/Modifiers/KMSHostCharge.cs
namespace LibTSforge.Modifiers
{
    using System;
    using System.IO;
    using PhysicalStore;
    using SPP;

    public static class KMSHostCharge
    {
        public static void Charge(PSVersion version, bool production, Guid actId)
        {
            if (actId == Guid.Empty)
            {
                actId = SLApi.GetDefaultActivationID(SLApi.WINDOWS_APP_ID, true);

                if (actId == Guid.Empty)
                {
                    throw new NotSupportedException("No applicable activation IDs found.");
                }
            }

            if (SLApi.GetPKeyChannel(SLApi.GetInstalledPkeyID(actId)) != "Volume:CSVLK")
            {
                throw new NotSupportedException("Non-Volume:CSVLK product key installed.");
            }

            Guid appId = SLApi.GetAppId(actId);
            int totalClients = 50;
            int currClients = 25;
            byte[] hwidBlock = Constants.UniversalHWIDBlock;
            string key = string.Format("SPPSVC\\{0}", appId);
            long ldapTimestamp = DateTime.Now.ToFileTime();

            byte[] cmidGuids = { };
            byte[] reqCounts = { };
            byte[] kmsChargeData = { };

            BinaryWriter writer = new BinaryWriter(new MemoryStream());

            if (version == PSVersion.Vista)
            {
                writer.Write(new byte[44]);
                writer.Seek(0, SeekOrigin.Begin);

                writer.Write(totalClients);
                writer.Write(43200);
                writer.Write(32);

                writer.Seek(20, SeekOrigin.Begin);
                writer.Write((byte)currClients);

                writer.Seek(32, SeekOrigin.Begin);
                writer.Write((byte)currClients);

                writer.Seek(0, SeekOrigin.End);

                for (int i = 0; i < currClients; i++)
                {
                    writer.Write(Guid.NewGuid().ToByteArray());
                    writer.Write(ldapTimestamp - (10 * (i + 1)));
                }

                kmsChargeData = writer.GetBytes();
            } 
            else
            {
                for (int i = 0; i < currClients; i++)
                {
                    writer.Write(ldapTimestamp - (10 * (i + 1)));
                    writer.Write(Guid.NewGuid().ToByteArray());
                }

                cmidGuids = writer.GetBytes();

                writer = new BinaryWriter(new MemoryStream());

                writer.Write(new byte[40]);

                writer.Seek(4, SeekOrigin.Begin);
                writer.Write((byte)currClients);

                writer.Seek(24, SeekOrigin.Begin);
                writer.Write((byte)currClients);

                reqCounts = writer.GetBytes();
            }

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                if (version != PSVersion.Vista)
                {
                    VariableBag kmsCountData = new VariableBag(version);
                    kmsCountData.Blocks.AddRange(new[]
                    {
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.BINARY,
                            KeyAsStr = "SppBindingLicenseData",
                            Value = hwidBlock
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.UINT,
                            Key = new byte[] { },
                            ValueAsInt = (uint)totalClients
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.UINT,
                            Key = new byte[] { },
                            ValueAsInt = 1051200000
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.UINT,
                            Key = new byte[] { },
                            ValueAsInt = (uint)currClients
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.BINARY,
                            Key = new byte[] { },
                            Value = cmidGuids
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.BINARY,
                            Key = new byte[] { },
                            Value = reqCounts
                        }
                    });

                    kmsChargeData = kmsCountData.Serialize();
                }

                string countVal = version == PSVersion.Vista ? "C8F6FFF1-79CE-404C-B150-F97991273DF1" : string.Format("msft:spp/kms/host/2.0/store/counters/{0}", appId);

                store.DeleteBlock(key, countVal);
                store.AddBlock(new PSBlock
                {
                    Type = BlockType.NAMED,
                    Flags = (version == PSVersion.WinModern) ? (uint)0x400 : 0,
                    KeyAsStr = key,
                    ValueAsStr = countVal,
                    Data = kmsChargeData
                });

                Logger.WriteLine(string.Format("Set charge count to {0} successfully.", currClients));
                store.Commit();
            }

            SPPUtils.RestartSPP(version);
        }
    }
}


// LibTSforge/Modifiers/RearmReset.cs
namespace LibTSforge.Modifiers
{
    using System.Collections.Generic;
    using System.Linq;
    using PhysicalStore;
    using SPP;

    public static class RearmReset
    {
        public static void Reset(PSVersion version, bool production)
        {
            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                List<PSBlock> blocks;

                if (version == PSVersion.Vista)
                {
                    blocks = store.FindBlocks("740D70D8-6448-4b2f-9063-4A7A463600C5").ToList();
                }
                else if (version == PSVersion.Win7)
                {
                    blocks = store.FindBlocks(0xA0000).ToList();
                }
                else
                {
                    blocks = store.FindBlocks("__##USERSEP-RESERVED##__$$REARM-COUNT$$").ToList();
                }

                foreach (PSBlock block in blocks)
                {
                    if (version == PSVersion.Vista)
                    {
                        store.DeleteBlock(block.KeyAsStr, block.ValueAsStr);
                    }
                    else if (version == PSVersion.Win7)
                    {
                        store.SetBlock(block.KeyAsStr, block.ValueAsInt, new byte[8]);
                    }
                    else
                    {
                        store.SetBlock(block.KeyAsStr, block.ValueAsStr, new byte[8]);
                    }
                }

                Logger.WriteLine("Successfully reset all rearm counters.");
                store.Commit();
            }
        }
    }
}


// LibTSforge/Modifiers/SetIIDParams.cs
namespace LibTSforge.Modifiers
{
    using PhysicalStore;
    using SPP;
    using System.IO;
    using System;

    public static class SetIIDParams
    {
        public static void SetParams(PSVersion version, bool production, Guid actId, PKeyAlgorithm algorithm, int group, int serial, ulong security)
        {
            if (version == PSVersion.Vista) throw new NotSupportedException("This feature is not supported on Windows Vista/Server 2008.");

            Guid appId;

            if (actId == Guid.Empty)
            {
                appId = SLApi.WINDOWS_APP_ID;
                actId = SLApi.GetDefaultActivationID(appId, true);

                if (actId == Guid.Empty)
                {
                    throw new Exception("No applicable activation IDs found.");
                }
            }
            else
            {
                appId = SLApi.GetAppId(actId);
            }

            Guid pkeyId = SLApi.GetInstalledPkeyID(actId);

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);
                PSBlock keyBlock = store.GetBlock(key, pkeyId.ToString());

                if (keyBlock == null)
                {
                    throw new InvalidDataException("Failed to get product key data for activation ID " + actId + ".");
                }

                VariableBag pkb = new VariableBag(keyBlock.Data, version);

                ProductKey pkey = new ProductKey
                {
                    Group = group,
                    Serial = serial,
                    Security = security,
                    Algorithm = algorithm,
                    Upgrade = false
                };

                string blockName = version == PSVersion.Win7 ? "SppPkeyShortAuthenticator" : "SppPkeyPhoneActivationData";
                pkb.SetBlock(blockName, pkey.GetPhoneData(version));
                store.SetBlock(key, pkeyId.ToString(), pkb.Serialize());
                store.Commit();
            }

            Logger.WriteLine("Successfully set IID parameters.");
        }
    }
}


// LibTSforge/Modifiers/TamperedFlagsDelete.cs
namespace LibTSforge.Modifiers
{
    using System.Linq;
    using PhysicalStore;
    using SPP;

    public static class TamperedFlagsDelete
    {
        public static void DeleteTamperFlags(PSVersion version, bool production)
        {
            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                if (version == PSVersion.Vista)
                {
                    DeleteFlag(store, "6BE8425B-E3CF-4e86-A6AF-5863E3DCB606");
                }
                else if (version == PSVersion.Win7)
                {
                    SetFlag(store, 0xA0001);
                }
                else
                {
                    DeleteFlag(store, "__##USERSEP-RESERVED##__$$RECREATED-FLAG$$");
                    DeleteFlag(store, "__##USERSEP-RESERVED##__$$RECOVERED-FLAG$$");
                }

                Logger.WriteLine("Successfully cleared the tamper state.");
                store.Commit();
            }

            SPPUtils.RestartSPP(version);
        }

        private static void DeleteFlag(IPhysicalStore store, string flag)
        {
            store.FindBlocks(flag).ToList().ForEach(block => store.DeleteBlock(block.KeyAsStr, block.ValueAsStr));
        }

        private static void SetFlag(IPhysicalStore store, uint flag)
        {
            store.FindBlocks(flag).ToList().ForEach(block => store.SetBlock(block.KeyAsStr, block.ValueAsInt, new byte[8]));
        }
    }
}


// LibTSforge/Modifiers/UniqueIdDelete.cs
namespace LibTSforge.Modifiers
{
    using System;
    using PhysicalStore;
    using SPP;

    public static class UniqueIdDelete
    {
        public static void DeleteUniqueId(PSVersion version, bool production, Guid actId)
        {
            if (version == PSVersion.Vista) throw new NotSupportedException("This feature is not supported on Windows Vista/Server 2008.");

            Guid appId;

            if (actId == Guid.Empty)
            {
                appId = SLApi.WINDOWS_APP_ID;
                actId = SLApi.GetDefaultActivationID(appId, true);

                if (actId == Guid.Empty)
                {
                    throw new Exception("No applicable activation IDs found.");
                }
            }
            else
            {
                appId = SLApi.GetAppId(actId);
            }

            Guid pkeyId = SLApi.GetInstalledPkeyID(actId);

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);
                PSBlock keyBlock = store.GetBlock(key, pkeyId.ToString());

                if (keyBlock == null)
                {
                    throw new Exception("No product key found.");
                }

                VariableBag pkb = new VariableBag(keyBlock.Data, version);

                pkb.DeleteBlock("SppPkeyUniqueIdToken");

                store.SetBlock(key, pkeyId.ToString(), pkb.Serialize());
                store.Commit();
            }

            Logger.WriteLine("Successfully removed Unique ID for product key ID " + pkeyId);
        }
    }
}


// LibTSforge/Activators/KMS4K.cs
namespace LibTSforge.Activators
{
    using System;
    using System.IO;
    using PhysicalStore;
    using SPP;

    public class KMS4k
    {
        public static void Activate(PSVersion version, bool production, Guid actId)
        {
            Guid appId;
            if (actId == Guid.Empty)
            {
                appId = SLApi.WINDOWS_APP_ID;
                actId = SLApi.GetDefaultActivationID(appId, true);

                if (actId == Guid.Empty)
                {
                    throw new NotSupportedException("No applicable activation IDs found.");
                }
            }
            else
            {
                appId = SLApi.GetAppId(actId);
            }

            if (SLApi.GetPKeyChannel(SLApi.GetInstalledPkeyID(actId)) != "Volume:GVLK")
            {
                throw new NotSupportedException("Non-Volume:GVLK product key installed.");
            }

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);

                ulong unknown = 0;
                ulong time1;
                ulong time2 = (ulong)DateTime.UtcNow.ToFileTime();
                ulong expiry = Constants.TimerMax;

                if (version == PSVersion.Vista || version == PSVersion.Win7)
                {
                    unknown = 0x800000000;
                    time1 = 0;
                }
                else
                {
                    long creationTime = BitConverter.ToInt64(store.GetBlock("__##USERSEP##\\$$_RESERVED_$$\\NAMESPACE__", "__##USERSEP-RESERVED##__$$GLOBAL-CREATION-TIME$$").Data, 0);
                    long tickCount = BitConverter.ToInt64(store.GetBlock("__##USERSEP##\\$$_RESERVED_$$\\NAMESPACE__", "__##USERSEP-RESERVED##__$$GLOBAL-TICKCOUNT-UPTIME$$").Data, 0);
                    long deltaTime = BitConverter.ToInt64(store.GetBlock(key, "__##USERSEP-RESERVED##__$$UP-TIME-DELTA$$").Data, 0);

                    time1 = (ulong)(creationTime + tickCount + deltaTime);
                    time2 /= 10000;
                    expiry /= 10000;
                }

                if (version == PSVersion.Vista)
                {
                    VistaTimer vistaTimer = new VistaTimer
                    {
                        Time = time2,
                        Expiry = Constants.TimerMax
                    };

                    string vistaTimerName = string.Format("msft:sl/timer/VLExpiration/VOLUME/{0}/{1}", appId, actId);

                    store.DeleteBlock(key, vistaTimerName);
                    store.DeleteBlock(key, actId.ToString());

                    BinaryWriter writer = new BinaryWriter(new MemoryStream());
                    writer.Write(Constants.KMSv4Response.Length);
                    writer.Write(Constants.KMSv4Response);
                    writer.Write(Constants.UniversalHWIDBlock);
                    byte[] kmsData = writer.GetBytes();

                    store.AddBlocks(new[]
                    {
                        new PSBlock
                        {
                            Type = BlockType.TIMER,
                            Flags = 0,
                            KeyAsStr = key,
                            ValueAsStr = vistaTimerName,
                            Data = vistaTimer.CastToArray()
                        },
                        new PSBlock
                        {
                            Type = BlockType.NAMED,
                            Flags = 0,
                            KeyAsStr = key,
                            ValueAsStr = actId.ToString(),
                            Data = kmsData
                        }
                    });
                }
                else
                {
                    byte[] hwidBlock = Constants.UniversalHWIDBlock;
                    byte[] kmsResp;

                    switch (version)
                    {
                        case PSVersion.Win7:
                            kmsResp = Constants.KMSv4Response;
                            break;
                        case PSVersion.Win8:
                            kmsResp = Constants.KMSv5Response;
                            break;
                        case PSVersion.WinBlue:
                        case PSVersion.WinModern:
                            kmsResp = Constants.KMSv6Response;
                            break;
                        default:
                            throw new NotSupportedException("Unsupported PSVersion.");
                    }

                    VariableBag kmsBinding = new VariableBag(version);

                    kmsBinding.Blocks.AddRange(new[]
                    {
                    new CRCBlockModern
                    {
                        DataType = CRCBlockType.BINARY,
                        Key = new byte[] { },
                        Value = kmsResp
                    },
                    new CRCBlockModern
                    {
                        DataType = CRCBlockType.STRING,
                        Key = new byte[] { },
                        ValueAsStr = "msft:rm/algorithm/hwid/4.0"
                    },
                    new CRCBlockModern
                    {
                        DataType = CRCBlockType.BINARY,
                        KeyAsStr = "SppBindingLicenseData",
                        Value = hwidBlock
                    }
                    });

                    if (version == PSVersion.WinModern)
                    {
                        kmsBinding.Blocks.AddRange(new[]
                        {
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.STRING,
                            Key = new byte[] { },
                            ValueAsStr = "massgrave.dev"
                        },
                        new CRCBlockModern
                        {
                            DataType = CRCBlockType.STRING,
                            Key = new byte[] { },
                            ValueAsStr = "6969"
                        }
                        });
                    }

                    byte[] kmsBindingData = kmsBinding.Serialize();

                    Timer kmsTimer = new Timer
                    {
                        Unknown = unknown,
                        Time1 = time1,
                        Time2 = time2,
                        Expiry = expiry
                    };

                    string storeVal = string.Format("msft:spp/kms/bind/2.0/store/{0}/{1}", appId, actId);
                    string timerVal = string.Format("msft:spp/kms/bind/2.0/timer/{0}/{1}", appId, actId);

                    store.DeleteBlock(key, storeVal);
                    store.DeleteBlock(key, timerVal);

                    store.AddBlocks(new[]
                    {
                    new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = (version == PSVersion.WinModern) ? (uint)0x400 : 0,
                        KeyAsStr = key,
                        ValueAsStr = storeVal,
                        Data = kmsBindingData
                    },
                    new PSBlock
                    {
                        Type = BlockType.TIMER,
                        Flags = (version == PSVersion.Win7) ? (uint)0 : 0x4,
                        KeyAsStr = key,
                        ValueAsStr = timerVal,
                        Data = kmsTimer.CastToArray()
                    }
                    });
                }
                store.Commit();
            }

            SPPUtils.RestartSPP(version);
            SLApi.FireStateChangedEvent(appId);
            Logger.WriteLine("Activated using KMS4k successfully.");
        }
    }
}


// LibTSforge/Activators/ZeroCID.cs
namespace LibTSforge.Activators
{
    using System;
    using System.IO;
    using System.Linq;
    using Crypto;
    using PhysicalStore;
    using SPP;

    public static class ZeroCID
    {
        private static void Deposit(Guid actId, string instId)
        {
            uint status = SLApi.DepositConfirmationID(actId, instId, Constants.ZeroCID);
            Logger.WriteLine(string.Format("Depositing fake CID status {0:X}", status));

            if (status != 0)
            {
                throw new InvalidOperationException("Failed to deposit fake CID.");
            }
        }

        public static void Activate(PSVersion version, bool production, Guid actId)
        {
            Guid appId;

            if (actId == Guid.Empty)
            {
                appId = SLApi.WINDOWS_APP_ID;
                actId = SLApi.GetDefaultActivationID(appId, false);

                if (actId == Guid.Empty)
                {
                    throw new NotSupportedException("No applicable activation IDs found.");
                }
            }
            else
            {
                appId = SLApi.GetAppId(actId);
            }

            if (!SLApi.IsPhoneActivatable(actId))
            {
                throw new NotSupportedException("Phone license is unavailable for this product.");
            }

            string instId = SLApi.GetInstallationID(actId);
            Guid pkeyId = SLApi.GetInstalledPkeyID(actId);

            if (version == PSVersion.Vista || version == PSVersion.Win7)
            {
                Deposit(actId, instId);
            }

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                byte[] hwidBlock = Constants.UniversalHWIDBlock;

                Logger.WriteLine("Activation ID: " + actId);
                Logger.WriteLine("Installation ID: " + instId);
                Logger.WriteLine("Product Key ID: " + pkeyId);

                byte[] iidHash;

                if (version == PSVersion.Vista)
                {
                    iidHash = CryptoUtils.SHA256Hash(Utils.EncodeString(instId)).Take(0x10).ToArray();
                }
                else if (version == PSVersion.Win7)
                {
                    iidHash = CryptoUtils.SHA256Hash(Utils.EncodeString(instId));
                }
                else
                {
                    iidHash = CryptoUtils.SHA256Hash(Utils.EncodeString(instId + '\0' + Constants.ZeroCID));
                }

                string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);
                PSBlock keyBlock = store.GetBlock(key, pkeyId.ToString());

                if (keyBlock == null)
                {
                    throw new InvalidDataException("Failed to get product key data for activation ID " + actId + ".");
                }

                VariableBag pkb = new VariableBag(keyBlock.Data, version);

                byte[] pkeyData;

                if (version == PSVersion.Vista)
                {
                    pkeyData = pkb.GetBlock("PKeyBasicInfo").Value;
                    string uniqueId = Utils.DecodeString(pkeyData.Skip(0x120).Take(0x80).ToArray());
                    string extPid = Utils.DecodeString(pkeyData.Skip(0x1A0).Take(0x80).ToArray());

                    uint group;
                    uint.TryParse(extPid.Split('-')[1], out group);

                    if (group == 0)
                    {
                        throw new FormatException("Extended PID has invalid format.");
                    }

                    ulong shortauth;

                    try
                    {
                        shortauth = BitConverter.ToUInt64(Convert.FromBase64String(uniqueId.Split('&')[1]), 0);
                    } 
                    catch
                    {
                        throw new FormatException("Key Unique ID has invalid format.");
                    }

                    shortauth |= (ulong)group << 41;
                    pkeyData = BitConverter.GetBytes(shortauth);
                }
                else if (version == PSVersion.Win7)
                {
                    pkeyData = pkb.GetBlock("SppPkeyShortAuthenticator").Value;
                }
                else
                {
                    pkeyData = pkb.GetBlock("SppPkeyPhoneActivationData").Value;
                }

                pkb.DeleteBlock("SppPkeyVirtual");
                store.SetBlock(key, pkeyId.ToString(), pkb.Serialize());

                BinaryWriter writer = new BinaryWriter(new MemoryStream());
                writer.Write(iidHash.Length);
                writer.Write(iidHash);
                writer.Write(hwidBlock.Length);
                writer.Write(hwidBlock);
                byte[] tsHwidData = writer.GetBytes();

                writer = new BinaryWriter(new MemoryStream());
                writer.Write(iidHash.Length);
                writer.Write(iidHash);
                writer.Write(pkeyData.Length);
                writer.Write(pkeyData);
                byte[] tsPkeyInfoData = writer.GetBytes();

                string phoneVersion = version == PSVersion.Vista ? "6.0" : "7.0";
                Guid indexSlid = version == PSVersion.Vista ? actId : pkeyId;
                string hwidBlockName = string.Format("msft:Windows/{0}/Phone/Cached/HwidBlock/{1}", phoneVersion, indexSlid);
                string pkeyInfoName = string.Format("msft:Windows/{0}/Phone/Cached/PKeyInfo/{1}", phoneVersion, indexSlid);

                store.DeleteBlock(key, hwidBlockName);
                store.DeleteBlock(key, pkeyInfoName);

                store.AddBlocks(new[] {
                    new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = 0,
                        KeyAsStr = key,
                        ValueAsStr = hwidBlockName,
                        Data = tsHwidData
                    }, 
                    new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = 0,
                        KeyAsStr = key,
                        ValueAsStr = pkeyInfoName,
                        Data = tsPkeyInfoData
                    }
                });
                store.Commit();
            }

            if (version != PSVersion.Vista && version != PSVersion.Win7)
            {
                Deposit(actId, instId);
            }

            SPPUtils.RestartSPP(version);
            SLApi.FireStateChangedEvent(appId);
            Logger.WriteLine("Activated using ZeroCID successfully.");
        }
    }
}


// LibTSforge/TokenStore/Common.cs
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
        void Commit();
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
            // Reject truncated/unknown input instead of silently constructing a blank store.
            const int maxStoreBytes = 128 * 1024 * 1024;
            if (TokensFile.Length < 0x24 + BLOCK_SIZE || TokensFile.Length > maxStoreBytes)
                throw new FormatException("Invalid token store size (supported maximum: 128 MiB).");
            TokensFile.Seek(0, SeekOrigin.Begin);
            byte[] bytes = new byte[(int)TokensFile.Length];
            int received = 0;
            while (received < bytes.Length)
            {
                int n = TokensFile.Read(bytes, received, bytes.Length - received);
                if (n == 0) throw new EndOfStreamException("Incomplete token store.");
                received += n;
            }
            if (BitConverter.ToUInt32(bytes, 0) != VERSION)
                throw new FormatException("Unsupported token store version.");
            if (!bytes.Skip(4).Take(32).SequenceEqual(CryptoUtils.SHA256Hash(bytes.Take(4).Concat(bytes.Skip(0x24)).ToArray())))
                throw new FormatException("Token store checksum mismatch.");

            List<TokenEntry> parsed = new List<TokenEntry>();
            HashSet<uint> visited = new HashSet<uint>();
            uint nextBlock = 0x24;
            using (BinaryReader reader = new BinaryReader(new MemoryStream(bytes, false)))
            {
                do
                {
                    uint block = nextBlock;
                    if (block < 0x24 || (long)block + BLOCK_SIZE > bytes.Length || !visited.Add(block))
                        throw new FormatException("Invalid/cyclic token block chain.");
                    byte[] blockHash = CryptoUtils.SHA256Hash(bytes.Skip((int)block).Take(BLOCK_SIZE - 32).ToArray());
                    if (!bytes.Skip((int)block + BLOCK_SIZE - 32).Take(32).SequenceEqual(blockHash))
                        throw new FormatException("Token block checksum mismatch.");
                    reader.BaseStream.Position = block;
                    if (reader.ReadUInt32() != block) throw new FormatException("Invalid block address.");
                    nextBlock = reader.ReadUInt32();
                    for (int i = 0; i < ENTRIES_PER_BLOCK; i++)
                    {
                        long entryOffset = (long)block + 8 + i * ENTRY_SIZE;
                        reader.BaseStream.Position = entryOffset;
                        if (reader.ReadUInt32() != entryOffset) throw new FormatException("Invalid entry address.");
                        uint state = reader.ReadUInt32();
                        if (state > 1) throw new FormatException("Invalid entry state.");
                        uint contentOffset = reader.ReadUInt32();
                        uint contentLength = reader.ReadUInt32();
                        uint allocLength = reader.ReadUInt32();
                        string name = reader.ReadNullTerminatedString(0x82);
                        string ext = reader.ReadNullTerminatedString(0x8);
                        byte[] contentData = new byte[0];
                        if (state == 1)
                        {
                            if (contentOffset < 0x24 || contentLength > maxStoreBytes || allocLength < contentLength ||
                                (long)contentOffset + 0x64 + contentLength > bytes.Length)
                                throw new FormatException("Token content outside file bounds.");
                            reader.BaseStream.Position = contentOffset;
                            if (!reader.ReadExactBytes(32).SequenceEqual(CONTS_HEADER) || reader.ReadUInt32() != contentLength)
                                throw new FormatException("Invalid token content header/length.");
                            byte[] hash = reader.ReadExactBytes(32);
                            contentData = reader.ReadExactBytes((int)contentLength);
                            if (contentData.Length != contentLength || !CryptoUtils.SHA256Hash(contentData).SequenceEqual(hash))
                                throw new FormatException("Token content checksum mismatch.");
                            if (!reader.ReadExactBytes(32).SequenceEqual(CONTS_FOOTER))
                                throw new FormatException("Invalid token content footer.");
                        }
                        parsed.Add(new TokenEntry { Name = name, Extension = ext, Data = contentData, Populated = state == 1 });
                    }
                } while (nextBlock != 0);
            }
            Entries = parsed;
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

                for (int eIndex = 0; eIndex < Math.Max(1, (Entries.Count + ENTRIES_PER_BLOCK - 1) / ENTRIES_PER_BLOCK) * ENTRIES_PER_BLOCK; eIndex++)
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
                        if (eIndex + 1 < Entries.Count)
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

            Array.Copy(tokensHash, 0, tokensData, 4, tokensHash.Length);
            StoreWriteBatch.Write(new FileStream[] { TokensFile }, new byte[][] { tokensData });
        }

        public void Commit() { Serialize(); }

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
            TokensFile = File.Open(tokensPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            try { Deserialize(); }
            catch { TokensFile.Close(); throw; }
        }

        public void Dispose()
        {
            TokensFile.Close();
        }
    }
}


// LibTSforge/PhysicalStore/Common.cs
namespace LibTSforge.PhysicalStore
{
    using System.Runtime.InteropServices;

    public enum BlockType : uint
    {
        NONE,
        NAMED,
        ATTRIBUTE,
        TIMER
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Timer
    {
        public ulong Unknown;
        public ulong Time1;
        public ulong Time2;
        public ulong Expiry;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct VistaTimer
    {
        public ulong Time;
        public ulong Expiry;
    }
}


// LibTSforge/PhysicalStore/IPhysicalStore.cs
namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;

    public class PSBlock
    {
        public BlockType Type;
        public uint Flags;
        public uint Unknown = 0;
        public byte[] Key;
        public string KeyAsStr
        {
            get
            {
                return Utils.DecodeString(Key);
            }
            set
            {
                Key = Utils.EncodeString(value);
            }
        }
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }
        public byte[] Data;
        public string DataAsStr
        {
            get
            {
                return Utils.DecodeString(Data);
            }
            set
            {
                Data = Utils.EncodeString(value);
            }
        }
        public uint DataAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Data, 0);
            }
            set
            {
                Data = BitConverter.GetBytes(value);
            }
        }
    }

    public interface IPhysicalStore : IDisposable
    {
        PSBlock GetBlock(string key, string value);
        PSBlock GetBlock(string key, uint value);
        void AddBlock(PSBlock block);
        void AddBlocks(IEnumerable<PSBlock> blocks);
        void SetBlock(string key, string value, byte[] data);
        void SetBlock(string key, string value, string data);
        void SetBlock(string key, string value, uint data);
        void SetBlock(string key, uint value, byte[] data);
        void SetBlock(string key, uint value, string data);
        void SetBlock(string key, uint value, uint data);
        void DeleteBlock(string key, string value);
        void DeleteBlock(string key, uint value);
        byte[] Serialize();
        void Deserialize(byte[] data);
        byte[] ReadRaw();
        void WriteRaw(byte[] data);
        void Commit();
        IEnumerable<PSBlock> FindBlocks(string valueSearch);
        IEnumerable<PSBlock> FindBlocks(uint valueSearch);
    }
}


// LibTSforge/PhysicalStore/PhysicalStoreModern.cs
namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Crypto;

    public class ModernBlock
    {
        public BlockType Type;
        public uint Flags;
        public uint Unknown;
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }
        public byte[] Data;
        public string DataAsStr
        {
            get
            {
                return Utils.DecodeString(Data);
            }
            set
            {
                Data = Utils.EncodeString(value);
            }
        }
        public uint DataAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Data, 0);
            }
            set
            {
                Data = BitConverter.GetBytes(value);
            }
        }

        public void Encode(BinaryWriter writer)
        {
            writer.Write((uint)Type);
            writer.Write(Flags);
            writer.Write((uint)Value.Length);
            writer.Write((uint)Data.Length);
            writer.Write(Unknown);
            writer.Write(Value);
            writer.Write(Data);
        }

        public static ModernBlock Decode(BinaryReader reader)
        {
            uint type = reader.ReadUInt32();
            uint flags = reader.ReadUInt32();

            uint valueLen = reader.ReadUInt32();
            uint dataLen = reader.ReadUInt32();
            uint unk3 = reader.ReadUInt32();

            byte[] value = reader.ReadExactBytes((int)valueLen);
            byte[] data = reader.ReadExactBytes((int)dataLen);

            return new ModernBlock
            {
                Type = (BlockType)type,
                Flags = flags,
                Unknown = unk3,
                Value = value,
                Data = data,
            };
        }
    }

    public sealed class PhysicalStoreModern : IPhysicalStore
    {
        private byte[] PreHeaderBytes = { };
        private readonly Dictionary<string, List<ModernBlock>> Data = new Dictionary<string, List<ModernBlock>>();
        private readonly FileStream TSFile;
        private readonly PSVersion Version;
        private readonly bool Production;

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(PreHeaderBytes);
            writer.Write(Data.Keys.Count);

            foreach (string key in Data.Keys)
            {
                List<ModernBlock> blocks = Data[key];
                byte[] keyNameEnc = Utils.EncodeString(key);

                writer.Write(keyNameEnc.Length);
                writer.Write(keyNameEnc);
                writer.Write(blocks.Count);
                writer.Align(4);

                foreach (ModernBlock block in blocks)
                {
                    block.Encode(writer);
                    writer.Align(4);
                }
            }

            return writer.GetBytes();
        }

        public void Deserialize(byte[] data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            PreHeaderBytes = reader.ReadExactBytes(8);

            while (reader.BaseStream.Position < data.Length - 0x4)
            {
                uint numKeys = reader.ReadUInt32();

                for (int i = 0; i < numKeys; i++)
                {
                    uint lenKeyName = reader.ReadUInt32();
                    string keyName = Utils.DecodeString(reader.ReadExactBytes((int)lenKeyName)); uint numValues = reader.ReadUInt32();

                    reader.Align(4);

                    Data[keyName] = new List<ModernBlock>();

                    for (int j = 0; j < numValues; j++)
                    {
                        Data[keyName].Add(ModernBlock.Decode(reader));
                        reader.Align(4);
                    }
                }
            }
        }

        public void AddBlock(PSBlock block)
        {
            if (!Data.ContainsKey(block.KeyAsStr))
            {
                Data[block.KeyAsStr] = new List<ModernBlock>();
            }

            Data[block.KeyAsStr].Add(new ModernBlock
            {
                Type = block.Type,
                Flags = block.Flags,
                Unknown = block.Unknown,
                Value = block.Value,
                Data = block.Data
            });
        }

        public void AddBlocks(IEnumerable<PSBlock> blocks)
        {
            foreach (PSBlock block in blocks)
            {
                AddBlock(block);
            }
        }

        public PSBlock GetBlock(string key, string value)
        {
            List<ModernBlock> blocks = Data[key];

            foreach (ModernBlock block in blocks)
            {
                if (block.ValueAsStr == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = Utils.EncodeString(key),
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public PSBlock GetBlock(string key, uint value)
        {
            List<ModernBlock> blocks = Data[key];

            foreach (ModernBlock block in blocks)
            {
                if (block.ValueAsInt == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = Utils.EncodeString(key),
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public void SetBlock(string key, string value, byte[] data)
        {
            List<ModernBlock> blocks = Data[key];

            for (int i = 0; i < blocks.Count; i++)
            {
                ModernBlock block = blocks[i];

                if (block.ValueAsStr == value)
                {
                    block.Data = data;
                    blocks[i] = block;
                    break;
                }
            }

            Data[key] = blocks;
        }

        public void SetBlock(string key, uint value, byte[] data)
        {
            List<ModernBlock> blocks = Data[key];

            for (int i = 0; i < blocks.Count; i++)
            {
                ModernBlock block = blocks[i];

                if (block.ValueAsInt == value)
                {
                    block.Data = data;
                    blocks[i] = block;
                    break;
                }
            }

            Data[key] = blocks;
        }

        public void SetBlock(string key, string value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, string value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void SetBlock(string key, uint value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, uint value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void DeleteBlock(string key, string value)
        {
            if (!Data.ContainsKey(key))
            {
                return;
            }

            List<ModernBlock> blocks = Data[key];

            foreach (ModernBlock block in blocks)
            {
                if (block.ValueAsStr == value)
                {
                    blocks.Remove(block);
                    break;
                }
            }

            Data[key] = blocks;
        }

        public void DeleteBlock(string key, uint value)
        {
            if (!Data.ContainsKey(key))
            {
                return;
            }

            List<ModernBlock> blocks = Data[key];

            foreach (ModernBlock block in blocks)
            {
                if (block.ValueAsInt == value)
                {
                    blocks.Remove(block);
                    break;
                }
            }

            Data[key] = blocks;
        }

        public PhysicalStoreModern(string tsPath, bool production, PSVersion version)
        {
            TSFile = File.Open(tsPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            try
            {
            Deserialize(PhysStoreCrypto.DecryptPhysicalStore(TSFile.ReadAllBytes(), production, version));
            TSFile.Seek(0, SeekOrigin.Begin);
            Version = version;
            Production = production;
        
            }
            catch { TSFile.Close(); throw; }
        }

        public void Dispose() { TSFile.Close(); }

        public void Commit()
        {
            byte[] data = PhysStoreCrypto.EncryptPhysicalStore(Serialize(), Production, Version);
            StoreWriteBatch.Write(new FileStream[] { TSFile }, new byte[][] { data });
        }

        public byte[] ReadRaw()
        {
            byte[] data = PhysStoreCrypto.DecryptPhysicalStore(TSFile.ReadAllBytes(), Production, Version);
            TSFile.Seek(0, SeekOrigin.Begin);
            return data;
        }

        public void WriteRaw(byte[] data)
        {
            data = PhysStoreCrypto.EncryptPhysicalStore(data, Production, Version);
            StoreWriteBatch.Write(new FileStream[] { TSFile }, new byte[][] { data });
        }

        public IEnumerable<PSBlock> FindBlocks(string valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (string key in Data.Keys)
            {
                List<ModernBlock> values = Data[key];

                foreach (ModernBlock block in values)
                {
                    if (block.ValueAsStr.Contains(valueSearch))
                    {
                        results.Add(new PSBlock
                        {
                            Type = block.Type,
                            Flags = block.Flags,
                            KeyAsStr = key,
                            Value = block.Value,
                            Data = block.Data
                        });
                    }
                }
            }

            return results;
        }

        public IEnumerable<PSBlock> FindBlocks(uint valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (string key in Data.Keys)
            {
                List<ModernBlock> values = Data[key];

                foreach (ModernBlock block in values)
                {
                    if (block.ValueAsInt == valueSearch)
                    {
                        results.Add(new PSBlock
                        {
                            Type = block.Type,
                            Flags = block.Flags,
                            KeyAsStr = key,
                            Value = block.Value,
                            Data = block.Data
                        });
                    }
                }
            }

            return results;
        }
    }
}


// LibTSforge/PhysicalStore/PhysicalStoreVista.cs
namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Crypto;

    public class VistaBlock
    {
        public BlockType Type;
        public uint Flags;
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }
        public byte[] Data;
        public string DataAsStr
        {
            get
            {
                return Utils.DecodeString(Data);
            }
            set
            {
                Data = Utils.EncodeString(value);
            }
        }
        public uint DataAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Data, 0);
            }
            set
            {
                Data = BitConverter.GetBytes(value);
            }
        }

        internal void Encode(BinaryWriter writer)
        {
            writer.Write((uint)Type);
            writer.Write(Flags);
            writer.Write(Value.Length);
            writer.Write(Data.Length);
            writer.Write(Value);
            writer.Write(Data);
        }

        internal static VistaBlock Decode(BinaryReader reader)
        {
            uint type = reader.ReadUInt32();
            uint flags = reader.ReadUInt32();

            int valueLen = reader.ReadInt32();
            int dataLen = reader.ReadInt32();

            byte[] value = reader.ReadExactBytes(valueLen);
            byte[] data = reader.ReadExactBytes(dataLen);
            return new VistaBlock
            {
                Type = (BlockType)type,
                Flags = flags,
                Value = value,
                Data = data,
            };
        }
    }

    public sealed class PhysicalStoreVista : IPhysicalStore
    {
        private byte[] PreHeaderBytes = { };
        private readonly List<VistaBlock> Blocks = new List<VistaBlock>();
        private readonly FileStream TSPrimary;
        private readonly FileStream TSSecondary;
        private readonly bool Production;

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(PreHeaderBytes);

            foreach (VistaBlock block in Blocks)
            {
                block.Encode(writer);
                writer.Align(4);
            }

            return writer.GetBytes();
        }

        public void Deserialize(byte[] data)
        {
            int len = data.Length;

            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            PreHeaderBytes = reader.ReadExactBytes(8);

            while (reader.BaseStream.Position < len - 0x14)
            {
                Blocks.Add(VistaBlock.Decode(reader));
                reader.Align(4);
            }
        }

        public void AddBlock(PSBlock block)
        {
            Blocks.Add(new VistaBlock
            {
                Type = block.Type,
                Flags = block.Flags,
                Value = block.Value,
                Data = block.Data
            });
        }

        public void AddBlocks(IEnumerable<PSBlock> blocks)
        {
            foreach (PSBlock block in blocks)
            {
                AddBlock(block);
            }
        }

        public PSBlock GetBlock(string key, string value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public PSBlock GetBlock(string key, uint value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public void SetBlock(string key, string value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                VistaBlock block = Blocks[i];

                if (block.ValueAsStr == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, uint value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                VistaBlock block = Blocks[i];

                if (block.ValueAsInt == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, string value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, string value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void SetBlock(string key, uint value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, uint value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void DeleteBlock(string key, string value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public void DeleteBlock(string key, uint value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public PhysicalStoreVista(string primaryPath, bool production)
        {
            TSPrimary = File.Open(primaryPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            try
            {
            TSSecondary = File.Open(primaryPath.Replace("-0.", "-1."), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Production = production;

            Deserialize(PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), production, PSVersion.Vista));
            TSPrimary.Seek(0, SeekOrigin.Begin);
        
            }
            catch { TSPrimary.Close(); if (TSSecondary != null) TSSecondary.Close(); throw; }
        }

        public void Dispose() { TSPrimary.Close(); TSSecondary.Close(); }

        public void Commit()
        {
            byte[] data = PhysStoreCrypto.EncryptPhysicalStore(Serialize(), Production, PSVersion.Vista);
            StoreWriteBatch.Write(new FileStream[] { TSPrimary, TSSecondary }, new byte[][] { data, data });
        }

        public byte[] ReadRaw()
        {
            byte[] data = PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), Production, PSVersion.Vista);
            TSPrimary.Seek(0, SeekOrigin.Begin);
            return data;
        }

        public void WriteRaw(byte[] data)
        {
            data = PhysStoreCrypto.EncryptPhysicalStore(data, Production, PSVersion.Vista);
            StoreWriteBatch.Write(new FileStream[] { TSPrimary, TSSecondary }, new byte[][] { data, data });
        }

        public IEnumerable<PSBlock> FindBlocks(string valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr.Contains(valueSearch))
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }

        public IEnumerable<PSBlock> FindBlocks(uint valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == valueSearch)
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }
    }
}


// LibTSforge/PhysicalStore/PhysicalStoreWin7.cs
namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Crypto;

    public class Win7Block
    {
        public BlockType Type;
        public uint Flags;
        public byte[] Key;
        public string KeyAsStr
        {
            get
            {
                return Utils.DecodeString(Key);
            }
            set
            {
                Key = Utils.EncodeString(value);
            }
        }
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }
        public byte[] Data;
        public string DataAsStr
        {
            get
            {
                return Utils.DecodeString(Data);
            }
            set
            {
                Data = Utils.EncodeString(value);
            }
        }
        public uint DataAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Data, 0);
            }
            set
            {
                Data = BitConverter.GetBytes(value);
            }
        }

        internal void Encode(BinaryWriter writer)
        {
            writer.Write((uint)Type);
            writer.Write(Flags);
            writer.Write(Key.Length);
            writer.Write(Value.Length);
            writer.Write(Data.Length);
            writer.Write(Key);
            writer.Write(Value);
            writer.Write(Data);
        }

        internal static Win7Block Decode(BinaryReader reader)
        {
            uint type = reader.ReadUInt32();
            uint flags = reader.ReadUInt32();

            int keyLen = reader.ReadInt32();
            int valueLen = reader.ReadInt32();
            int dataLen = reader.ReadInt32();

            byte[] key = reader.ReadExactBytes(keyLen);
            byte[] value = reader.ReadExactBytes(valueLen);
            byte[] data = reader.ReadExactBytes(dataLen);
            return new Win7Block
            {
                Type = (BlockType)type,
                Flags = flags,
                Key = key,
                Value = value,
                Data = data,
            };
        }
    }

    public sealed class PhysicalStoreWin7 : IPhysicalStore
    {
        private byte[] PreHeaderBytes = { };
        private readonly List<Win7Block> Blocks = new List<Win7Block>();
        private readonly FileStream TSPrimary;
        private readonly FileStream TSSecondary;
        private readonly bool Production;

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(PreHeaderBytes);

            foreach (Win7Block block in Blocks)
            {
                block.Encode(writer);
                writer.Align(4);
            }

            return writer.GetBytes();
        }

        public void Deserialize(byte[] data)
        {
            int len = data.Length;

            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            PreHeaderBytes = reader.ReadExactBytes(8);

            while (reader.BaseStream.Position < len - 0x14)
            {
                Blocks.Add(Win7Block.Decode(reader));
                reader.Align(4);
            }
        }

        public void AddBlock(PSBlock block)
        {
            Blocks.Add(new Win7Block
            {
                Type = block.Type,
                Flags = block.Flags,
                Key = block.Key,
                Value = block.Value,
                Data = block.Data
            });
        }

        public void AddBlocks(IEnumerable<PSBlock> blocks)
        {
            foreach (PSBlock block in blocks)
            {
                AddBlock(block);
            }
        }

        public PSBlock GetBlock(string key, string value)
        {
            foreach (Win7Block block in Blocks)
            {
                if (block.KeyAsStr == key && block.ValueAsStr == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = block.Key,
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public PSBlock GetBlock(string key, uint value)
        {
            foreach (Win7Block block in Blocks)
            {
                if (block.KeyAsStr == key && block.ValueAsInt == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = block.Key,
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public void SetBlock(string key, string value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                Win7Block block = Blocks[i];

                if (block.KeyAsStr == key && block.ValueAsStr == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, uint value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                Win7Block block = Blocks[i];

                if (block.KeyAsStr == key && block.ValueAsInt == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, string value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, string value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void SetBlock(string key, uint value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, uint value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void DeleteBlock(string key, string value)
        {
            foreach (Win7Block block in Blocks)
            {
                if (block.KeyAsStr == key && block.ValueAsStr == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public void DeleteBlock(string key, uint value)
        {
            foreach (Win7Block block in Blocks)
            {
                if (block.KeyAsStr == key && block.ValueAsInt == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public PhysicalStoreWin7(string primaryPath, bool production)
        {
            TSPrimary = File.Open(primaryPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            try
            {
            TSSecondary = File.Open(primaryPath.Replace("-0.", "-1."), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Production = production;

            Deserialize(PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), production, PSVersion.Win7));
            TSPrimary.Seek(0, SeekOrigin.Begin);
        
            }
            catch { TSPrimary.Close(); if (TSSecondary != null) TSSecondary.Close(); throw; }
        }

        public void Dispose() { TSPrimary.Close(); TSSecondary.Close(); }

        public void Commit()
        {
            byte[] data = PhysStoreCrypto.EncryptPhysicalStore(Serialize(), Production, PSVersion.Win7);
            StoreWriteBatch.Write(new FileStream[] { TSPrimary, TSSecondary }, new byte[][] { data, data });
        }

        public byte[] ReadRaw()
        {
            byte[] data = PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), Production, PSVersion.Win7);
            TSPrimary.Seek(0, SeekOrigin.Begin);
            return data;
        }

        public void WriteRaw(byte[] data)
        {
            data = PhysStoreCrypto.EncryptPhysicalStore(data, Production, PSVersion.Win7);
            StoreWriteBatch.Write(new FileStream[] { TSPrimary, TSSecondary }, new byte[][] { data, data });
        }

        public IEnumerable<PSBlock> FindBlocks(string valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (Win7Block block in Blocks)
            {
                if (block.ValueAsStr.Contains(valueSearch))
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = block.Key,
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }

        public IEnumerable<PSBlock> FindBlocks(uint valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (Win7Block block in Blocks)
            {
                if (block.ValueAsInt == valueSearch)
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = block.Key,
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }
    }
}


// LibTSforge/PhysicalStore/VariableBag.cs
namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    public enum CRCBlockType : uint
    {
        UINT = 1 << 0,
        STRING = 1 << 1,
        BINARY = 1 << 2
    }

    public abstract class CRCBlock
    {
        public CRCBlockType DataType;
        public byte[] Key;
        public string KeyAsStr
        {
            get
            {
                return Utils.DecodeString(Key);
            }
            set
            {
                Key = Utils.EncodeString(value);
            }
        }
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }

        public abstract void Encode(BinaryWriter writer);
        public abstract void Decode(BinaryReader reader);
        public abstract uint CRC();
    }

    public class CRCBlockVista : CRCBlock
    {
        public override void Encode(BinaryWriter writer)
        {
            uint crc = CRC();
            writer.Write((uint)DataType);
            writer.Write(0);
            writer.Write(Key.Length);
            writer.Write(Value.Length);
            writer.Write(crc);

            writer.Write(Key);

            writer.Write(Value);
        }

        public override void Decode(BinaryReader reader)
        {
            uint type = reader.ReadUInt32();
            reader.ReadUInt32();
            uint lenName = reader.ReadUInt32();
            uint lenVal = reader.ReadUInt32();
            uint crc = reader.ReadUInt32();

            byte[] key = reader.ReadExactBytes((int)lenName);
            byte[] value = reader.ReadExactBytes((int)lenVal);

            DataType = (CRCBlockType)type;
            Key = key;
            Value = value;

            if (CRC() != crc)
            {
                throw new InvalidDataException("Invalid CRC in variable bag.");
            }
        }

        public override uint CRC()
        {
            return Utils.CRC32(Value);
        }
    }

    public class CRCBlockModern : CRCBlock
    {
        public override void Encode(BinaryWriter writer)
        {
            uint crc = CRC();
            writer.Write(crc);
            writer.Write((uint)DataType);
            writer.Write(Key.Length);
            writer.Write(Value.Length);

            writer.Write(Key);
            writer.Align(8);

            writer.Write(Value);
            writer.Align(8);
        }

        public override void Decode(BinaryReader reader)
        {
            uint crc = reader.ReadUInt32();
            uint type = reader.ReadUInt32();
            uint lenName = reader.ReadUInt32();
            uint lenVal = reader.ReadUInt32();

            byte[] key = reader.ReadExactBytes((int)lenName);
            reader.Align(8);

            byte[] value = reader.ReadExactBytes((int)lenVal);
            reader.Align(8);

            DataType = (CRCBlockType)type;
            Key = key;
            Value = value;

            if (CRC() != crc)
            {
                throw new InvalidDataException("Invalid CRC in variable bag.");
            }
        }

        public override uint CRC()
        {
            BinaryWriter wtemp = new BinaryWriter(new MemoryStream());
            wtemp.Write(0);
            wtemp.Write((uint)DataType);
            wtemp.Write(Key.Length);
            wtemp.Write(Value.Length);
            wtemp.Write(Key);
            wtemp.Write(Value);
            return Utils.CRC32(wtemp.GetBytes());
        }
    }

    public class VariableBag
    {
        public List<CRCBlock> Blocks = new List<CRCBlock>();
        private readonly PSVersion Version;

        private void Deserialize(byte[] data)
        {
            int len = data.Length;

            BinaryReader reader = new BinaryReader(new MemoryStream(data));

            while (reader.BaseStream.Position < len - 0x10)
            {
                CRCBlock block;

                if (Version == PSVersion.Vista)
                {
                    block = new CRCBlockVista();
                }
                else
                {
                    block = new CRCBlockModern();
                }

                block.Decode(reader);
                Blocks.Add(block);
            }
        }

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());

            foreach (CRCBlock block in Blocks)
            {
                if (Version == PSVersion.Vista)
                {
                    ((CRCBlockVista)block).Encode(writer);
                } else
                {
                    ((CRCBlockModern)block).Encode(writer);
                }
            }

            return writer.GetBytes();
        }

        public CRCBlock GetBlock(string key)
        {
            foreach (CRCBlock block in Blocks)
            {
                if (block.KeyAsStr == key)
                {
                    return block;
                }
            }

            return null;
        }

        public void SetBlock(string key, byte[] value)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                CRCBlock block = Blocks[i];

                if (block.KeyAsStr == key)
                {
                    block.Value = value;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void DeleteBlock(string key)
        {
            foreach (CRCBlock block in Blocks)
            {
                if (block.KeyAsStr == key)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public VariableBag(byte[] data, PSVersion version)
        {
            Version = version;
            Deserialize(data);
        }

        public VariableBag(PSVersion version)
        {
            Version = version;
        }
    }
}

// Local hardening patch. Does not change license generation or activation protocols.
namespace LibTSforge
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    // A batch is explicit: disposing after an exception NEVER saves pending data.
    // File.Replace is atomic per file, not across files or across power loss.
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
            for (string p = Path.GetFullPath(path); !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p))
            {
                if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Refusing a redirected store path: " + p);
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

        private static void ReplaceAll(string[] names, byte[][] data)
        {
            string suffix = ".mas-safer-" + Guid.NewGuid().ToString("N");
            string[] temporary = names.Select(n => n + suffix + ".tmp").ToArray();
            string[] backups = names.Select(n => n + suffix + ".bak").ToArray();
            int replaced = 0;
            try
            {
                // Stage every output before touching ANY destination. No truncate/write fallback.
                for (int i = 0; i < names.Length; i++)
                {
                    CheckPath(names[i]);
                    using (FileStream output = new FileStream(temporary[i], FileMode.CreateNew,
                        FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    {
                        output.Write(data[i], 0, data[i].Length);
                        output.Flush();
                    }
                    if (!File.ReadAllBytes(temporary[i]).SequenceEqual(data[i]))
                        throw new IOException("Staged store verification failed.");
                }
                for (int i = 0; i < names.Length; i++)
                {
                    CheckPath(names[i]);
                    File.Replace(temporary[i], names[i], backups[i]);
                    replaced++;
                }
            }
            catch (Exception writeError)
            {
                string rollbackErrors = "";
                for (int i = replaced - 1; i >= 0; i--)
                {
                    string restore = names[i] + suffix + ".restore";
                    try
                    {
                        CheckPath(names[i]);
                        File.Copy(backups[i], restore, false);
                        File.Replace(restore, names[i], null);
                    }
                    catch (Exception ex) { rollbackErrors += " " + names[i] + ": " + ex.Message; }
                }
                throw new IOException("Store write failed. Backups retained with suffix " + suffix +
                    (rollbackErrors.Length == 0 ? ". Completed replacements rolled back." :
                    ". MANUAL RECOVERY REQUIRED:" + rollbackErrors), writeError);
            }
            finally
            {
                foreach (string path in temporary)
                {
                    try { if (File.Exists(path)) File.Delete(path); }
                    catch { /* Keep staging file rather than hiding the primary error. */ }
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
