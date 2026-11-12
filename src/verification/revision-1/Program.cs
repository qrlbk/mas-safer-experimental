using System;
using System.IO;
using System.Linq;
using LibTSforge;
using LibTSforge.Crypto;
using LibTSforge.TokenStore;
using LibTSforge.PhysicalStore;

public static class TestFaults { public static int FailAt = -1; }
class Program
{
    static string root;
    static int passed;
    static void Check(bool ok, string name) { if (!ok) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); passed++; }
    static string Seed(string name, int count) { string p=Path.Combine(root,name); File.Copy(Path.Combine(root,"fixtures",count+".dat"),p,true); return p; }
    static void GlobalHash(byte[] b) { Array.Copy(CryptoUtils.SHA256Hash(b.Take(4).Concat(b.Skip(36)).ToArray()),0,b,4,32); }
    static void BlockHash(byte[] b) { Array.Copy(CryptoUtils.SHA256Hash(b.Skip(36).Take(0x4000).ToArray()),0,b,36+0x4000,32); GlobalHash(b); }
    static void Rejected(byte[] b,string name) {
        string p=Path.Combine(root,"invalid.dat"); File.WriteAllBytes(p,b); bool rejected=false;
        try { using(var s=new TokenStoreModern(p)){} } catch(FormatException) { rejected=true; }
        Check(rejected && File.ReadAllBytes(p).SequenceEqual(b),name);
        using(var f=File.Open(p,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {} // constructor failure released its lock
    }
    static void Main(string[] args)
    {
        root=args[0];
        string p=Seed("exception.dat",1); byte[] before=File.ReadAllBytes(p);
        try { using(var s=new TokenStoreModern(p)){s.SetEntry("entry0","xml",new byte[]{9});throw new Exception("simulated operation failure");} } catch(Exception){}
        Check(File.ReadAllBytes(p).SequenceEqual(before),"exception does not commit token changes");
        using(var s=new TokenStoreModern(p)){}
        Check(File.ReadAllBytes(p).SequenceEqual(before),"read-only open/close preserves every byte");
        using(var s=new TokenStoreModern(p)){s.SetEntry("entry0","xml",new byte[]{9});s.Commit();}
        using(var s=new TokenStoreModern(p)){Check(s.GetEntry("entry0","xml").Data.SequenceEqual(new byte[]{9}),"explicit token commit persists data");}
        string[] backups=Directory.GetFiles(root,"exception.dat.mas-safer-*.bak");
        Check(backups.Any(b=>File.ReadAllBytes(b).SequenceEqual(before)),"atomic commit retains exact original backup");
        foreach(int n in new int[]{0,1,103,104,206}) {
            p=Seed("roundtrip"+n+".dat",n);
            using(var s=new TokenStoreModern(p)){s.Commit();}
            byte[] once=File.ReadAllBytes(p);
            for(int cycle=0;cycle<3;cycle++) using(var s=new TokenStoreModern(p)){for(int i=0;i<n;i++) if(s.GetEntry("entry"+i,"xml").Data[3]!=(byte)i)throw new Exception("content lost");s.Commit();}
            Check(File.ReadAllBytes(p).SequenceEqual(once),"stable serialization and contents: "+n+" entries");
        }
        Rejected(new byte[]{1,2,3},"truncated input rejected, preserved, unlocked");
        Rejected(new byte[0],"empty input rejected");
        byte[] valid=File.ReadAllBytes(Path.Combine(root,"fixtures","1.dat"));
        byte[] bad=(byte[])valid.Clone(); bad[4]^=1; Rejected(bad,"global hash mismatch rejected");
        bad=(byte[])valid.Clone();bad[36+0x4000]^=1;GlobalHash(bad);Rejected(bad,"block hash mismatch rejected");
        bad=(byte[])valid.Clone();int content=BitConverter.ToInt32(bad,0x34);bad[content+0x44]^=1;GlobalHash(bad);Rejected(bad,"payload hash mismatch rejected even with valid global hash");
        bad=(byte[])valid.Clone();Array.Copy(BitConverter.GetBytes((uint)36),0,bad,40,4);BlockHash(bad);Rejected(bad,"cyclic block chain rejected");
        bad=(byte[])valid.Clone();Array.Copy(BitConverter.GetBytes(uint.MaxValue),0,bad,0x34,4);BlockHash(bad);Rejected(bad,"out-of-bounds payload offset rejected");
        bad=(byte[])valid.Clone();Array.Copy(BitConverter.GetBytes(uint.MaxValue),0,bad,0x38,4);BlockHash(bad);Rejected(bad,"oversized payload rejected without allocation");
        bad=(byte[])valid.Clone();bad[0]=4;GlobalHash(bad);Rejected(bad,"unknown version rejected");
        string a=Path.Combine(root,"a.dat"), bpath=Path.Combine(root,"b.dat");
        File.WriteAllBytes(a,new byte[]{1});File.WriteAllBytes(bpath,new byte[]{2});
        using(var batch=new StoreWriteBatch()) {
            using(var fa=File.Open(a,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                StoreWriteBatch.Write(new FileStream[]{fa},new byte[][]{new byte[]{8}});
        }
        Check(File.ReadAllBytes(a)[0]==1,"abandoned file batch writes nothing");
        using(var batch=new StoreWriteBatch()) {
            using(var fa=File.Open(a,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
            using(var fb=File.Open(bpath,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                StoreWriteBatch.Write(new FileStream[]{fa,fb},new byte[][]{new byte[]{8},new byte[]{9}});
            batch.Commit();
        }
        Check(File.ReadAllBytes(a)[0]==8 && File.ReadAllBytes(bpath)[0]==9,"explicit multi-file batch persists both outputs");
#if FAULT_TESTS
        TestFaults.FailAt=1;bool failed=false;
        try {
            using(var fa=File.Open(a,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
            using(var fb=File.Open(bpath,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                StoreWriteBatch.Write(new FileStream[]{fa,fb},new byte[][]{new byte[]{3},new byte[]{4}});
        } catch(IOException){failed=true;} finally {TestFaults.FailAt=-1;}
        Check(failed && File.ReadAllBytes(a)[0]==8 && File.ReadAllBytes(bpath)[0]==9,"failure replacing SECOND file rolls back FIRST file");
#endif
        bool missing=false;try{using(var s=new TokenStoreModern(Path.Combine(root,"missing.dat"))){} }catch(FileNotFoundException){missing=true;}
        Check(missing && !File.Exists(Path.Combine(root,"missing.dat")),"missing store is not silently created");
        foreach(PSVersion version in new PSVersion[]{PSVersion.Vista,PSVersion.Win7,PSVersion.Win8,PSVersion.WinBlue,PSVersion.WinModern}) {
            string primary=Path.Combine(root,version+"-0.dat"),secondary=Path.Combine(root,version+"-1.dat");
            byte[] encrypted=PhysStoreCrypto.EncryptPhysicalStore(new byte[12],false,version);
            File.WriteAllBytes(primary,encrypted);File.WriteAllBytes(secondary,encrypted);
            try { using(var store=OpenPhysical(primary,version)){store.AddBlock(new PSBlock{Type=BlockType.NAMED,KeyAsStr="test",ValueAsStr="value",Data=new byte[]{5}});throw new Exception("synthetic failure");}}catch(Exception){}
            Check(File.ReadAllBytes(primary).SequenceEqual(encrypted) && File.ReadAllBytes(secondary).SequenceEqual(encrypted),version+" dispose on failure preserves encrypted stores");
            using(var store=OpenPhysical(primary,version)){store.AddBlock(new PSBlock{Type=BlockType.NAMED,KeyAsStr="test",ValueAsStr="value",Data=new byte[]{5}});store.Commit();}
            using(var store=OpenPhysical(primary,version)){Check(store.GetBlock("test","value").Data[0]==5,version+" explicit physical commit round-trip");}
            if(version==PSVersion.Vista || version==PSVersion.Win7) Check(File.ReadAllBytes(primary).SequenceEqual(File.ReadAllBytes(secondary)),version+" mirrored files committed identically");
        }
        Console.WriteLine("TOTAL PASSED: "+passed);
    }
    static IPhysicalStore OpenPhysical(string path,PSVersion version) {
        if(version==PSVersion.Vista)return new PhysicalStoreVista(path,false);
        if(version==PSVersion.Win7)return new PhysicalStoreWin7(path,false);
        return new PhysicalStoreModern(path,false,version);
    }
}
