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
                            if (!reader.ReadBytes(32).SequenceEqual(CONTS_HEADER) || reader.ReadUInt32() != contentLength)
                                throw new FormatException("Invalid token content header/length.");
                            byte[] hash = reader.ReadBytes(32);
                            contentData = reader.ReadBytes((int)contentLength);
                            if (contentData.Length != contentLength || !CryptoUtils.SHA256Hash(contentData).SequenceEqual(hash))
                                throw new FormatException("Token content checksum mismatch.");
                            if (!reader.ReadBytes(32).SequenceEqual(CONTS_FOOTER))
                                throw new FormatException("Invalid token content footer.");
                        }
                        parsed.Add(new TokenEntry { Name = name, Extension = ext, Data = contentData, Populated = state == 1 });
                    }
                } while (nextBlock != 0);
            }
            Entries = parsed;
        }
