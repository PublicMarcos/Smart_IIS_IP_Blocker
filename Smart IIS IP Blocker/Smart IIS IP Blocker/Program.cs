using Microsoft.Web.Administration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Smart_IIS_IP_Blocker
{
    class Program
    {
        private static Dictionary<string, IP> AllIPs { get; set; }
        private static Config MainConfig { get; set; }
        private static int BlockedCount { get; set; }
        static void Main(string[] args)
        {
            if (args.Length > 3)
            {
                string ConfigPath = string.Empty, IPTablePath = string.Empty, LogPath = string.Empty, LogsFolderPath = string.Empty;
                var CheckInterval = TimeSpan.Parse("00:00:10");
                AllIPs = new Dictionary<string, IP>();
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i].StartsWith("-config=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        ConfigPath = args[i].Split(new string[1] { "-config=" }, StringSplitOptions.None)[1];
                    }
                    else if (args[i].StartsWith("-log=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        LogPath = args[i].Split(new string[1] { "-log=" }, StringSplitOptions.None)[1];
                    }
                    else if (args[i].StartsWith("-iptable=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        IPTablePath = args[i].Split(new string[1] { "-iptable=" }, StringSplitOptions.None)[1];
                    }
                    else if (args[i].StartsWith("-logroot=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        LogsFolderPath = args[i].Split(new string[1] { "-logroot=" }, StringSplitOptions.None)[1];
                    }
                    else if (args[i].StartsWith("-checkinterval=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        TimeSpan.TryParse(args[i].Split(new string[1] { "-checkinterval=" }, StringSplitOptions.None)[1], out CheckInterval);
                    }
                }
                if (string.IsNullOrWhiteSpace(ConfigPath) || string.IsNullOrWhiteSpace(LogPath) || string.IsNullOrWhiteSpace(IPTablePath) || string.IsNullOrWhiteSpace(LogsFolderPath) || !File.Exists(ConfigPath) || !Directory.Exists(LogsFolderPath))
                {
                    Console.WriteLine("Falsche Startparameter");
                    Environment.Exit(87);
                }
                else
                {
                    MainConfig = new Config(ConfigPath, IPTablePath, LogPath);
                    if (!MainConfig.Valid)
                    {
                        Console.WriteLine("Falsche Konfiguration");
                        Environment.Exit(87);
                    }
                }
                while (true)
                {
                    if (File.Exists(IPTablePath))
                    {
                        var RAWData = File.ReadAllText(IPTablePath);
                        var RAWIPs = RAWData.Split(new string[1] { "," }, StringSplitOptions.RemoveEmptyEntries);//Sind alle bereits geblockt
                        for (int i = 0; i < RAWIPs.Length; i++)
                        {
                            AllIPs.Add(RAWIPs[i], new IP(RAWIPs[i], true));
                        }
                    }
                    var AllLogs = Directory.GetFiles(LogsFolderPath, "*.log", SearchOption.TopDirectoryOnly);
                    FileInfo CurInfo;
                    for (int i = 0; i < AllLogs.Length; i++)
                    {
                        CurInfo = new FileInfo(AllLogs[i]);
                        if (CurInfo.LastWriteTime > DateTime.Now.AddDays(-MainConfig.MaxLogAge))
                        {
                            ReadLog(AllLogs[i]);
                        }
                    }
                    var IPSB = new StringBuilder();
                    foreach (var CurIP in AllIPs.Values)
                    {
                        if (CurIP.Blocked)
                        {
                            IPSB.Append(CurIP.IPAdress + ",");
                            if (!CurIP.AlreadyBlocked)
                            {
                                if (!BlockIP(CurIP.IPAdress))
                                {
                                    ErrorReport(string.Format("Datum: {0:G}", DateTime.Now) + " - Unbekannter Fehler beim hinzufügen der IPs in die Webseiten");
                                    break;
                                }
                                GC.Collect();
                                BlockedCount++;
                            }
                        }
                    }
                    if ((IPSB.Length > 0) && (BlockedCount > 0))
                    {
                        IPSB.Remove(IPSB.Length - 1, 1);
                        if (File.Exists(IPTablePath))
                        {
                            File.Delete(IPTablePath);
                        }
                        File.WriteAllText(IPTablePath, IPSB.ToString());
                        ErrorReport(string.Format("Datum: {0:G}", DateTime.Now) + " - Anzahl an geblockten IP's: " + BlockedCount.ToString());
                    }

                    AllIPs.Clear();
                    BlockedCount = 0;
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced);

                    Thread.Sleep((int)CheckInterval.TotalMilliseconds);
                }
            }
        }

        private static void ErrorReport(string Message)
        {
            Console.WriteLine(Message);
            File.AppendAllLines(MainConfig.LogPath, new string[1] { Message });
        }
        private static bool ReadLog(string LogFilePath)
        {
            try
            {
                var RAWData = File.ReadAllLines(LogFilePath, Encoding.UTF8);
                var LockThis = new object();
                Parallel.For(0, RAWData.Length, new ParallelOptions { MaxDegreeOfParallelism = RAWData.Length }, i =>
                {
                    if ((RAWData[i].Length > 0) && !RAWData[i].StartsWith("#"))
                    {
                        IP CurIP;
                        int HTTPError;
                        DateTime LogEntryDate;
                        long ServerToClientBytes, ClientToServerBytes;
                        var RAWItems = RAWData[i].Split(' ');
                        if (RAWItems.Length > 15)
                        {
                            lock (LockThis)
                            {
                                if (!AllIPs.TryGetValue(RAWItems[8], out CurIP))
                                {
                                    CurIP = new IP(RAWItems[8], false);
                                    AllIPs.Add(RAWItems[8], CurIP);
                                }
                            }
                            if (!CurIP.Blocked)
                            {
                                if (DateTime.TryParse(RAWItems[0] + " " + RAWItems[1], out LogEntryDate) && (LogEntryDate > DateTime.Now.AddDays(-MainConfig.TriggerAtTransferredSizePeriod)) && long.TryParse(RAWItems[14], out ServerToClientBytes) && long.TryParse(RAWItems[15], out ClientToServerBytes))
                                {
                                    Interlocked.Add(ref CurIP.TransferredBytes, ServerToClientBytes + ClientToServerBytes);
                                }
                                if (CurIP.TransferredBytes > MainConfig.TriggerAtTransferredSize)
                                {
                                    CurIP.Blocked = true;
                                }
                                else if (DateTime.TryParse(RAWItems[0] + " " + RAWItems[1], out LogEntryDate) && (LogEntryDate > DateTime.Now.AddDays(-MainConfig.TriggerLogAgeInDays)))
                                {
                                    if (MainConfig.BlackListedAgents.Any(RAWItems[9].ToLowerInvariant().Contains))
                                    {
                                        CurIP.Blocked = true;
                                    }
                                    else if (int.TryParse(RAWItems[11], out HTTPError) && MainConfig.TriggerCodes.Contains(HTTPError) && ((MainConfig.TriggerLevel == 1) || ((MainConfig.TriggerLevel == 2) && (!RAWItems[4].Split('/').Last().Contains("."))) || ((MainConfig.TriggerLevel == 3) && RAWItems[4].EndsWith("/"))))
                                    {
                                        Interlocked.Increment(ref CurIP.ErrorCount);
                                        if (CurIP.ErrorCount >= MainConfig.TriggerHitPoints)
                                        {
                                            CurIP.Blocked = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
            catch
            {
                ErrorReport(string.Format("Datum: {0:G}", DateTime.Now) + " - Unbekannter Fehler beim Lesen des Logs " + LogFilePath);
            }
            return true;
        }

        private static bool BlockIP(string IPAdress)
        {
            try
            {
                using (var serverManager = new ServerManager())
                {
                    var config = serverManager.GetApplicationHostConfiguration();
                    ConfigurationSection ipSecuritySection;
                    ConfigurationElementCollection ipSecurityCollection;
                    ConfigurationElement addElement;
                    foreach (string Websitename in MainConfig.Webseites)
                    {
                        ipSecuritySection = config.GetSection("system.webServer/security/ipSecurity", Websitename);
                        ipSecurityCollection = ipSecuritySection.GetCollection();
                        addElement = ipSecurityCollection.CreateElement("add");
                        addElement["ipAddress"] = IPAdress;
                        addElement["allowed"] = false;
                        ipSecurityCollection.Add(addElement);
                        serverManager.CommitChanges();
                    }
                }
            }
            catch
            {
                return false;
            }
            return true;
        }
    }
    internal sealed class Config
    {
        internal Config(string ConfigPath, string IPTablePath, string LogPath)
        {
            this.ConfigPath = ConfigPath;
            this.LogPath = LogPath;
            this.IPTablePath = IPTablePath;
            var RawData = File.ReadAllLines(ConfigPath);
            this.TriggerCodes = new HashSet<int>();
            this.BlackListedAgents = new HashSet<string>();
            this.Webseites = new HashSet<string>();
            for (int i = 0; i < RawData.Length; i++)
            {
                var RAWItems = RawData[i].Split('=');
                switch (RAWItems[0].ToLowerInvariant())
                {
                    case "triggerlevel":
                        int.TryParse(RAWItems[1], out TriggerLevel);
                        break;
                    case "triggercodes":
                        var CurCode = 0;
                        if (RAWItems[1].Contains(","))
                        {
                            var RAWSubitems = RAWItems[1].Split(',');
                            for (int i2 = 0; i2 < RAWSubitems.Length; i2++)
                            {
                                if (int.TryParse(RAWSubitems[i2], out CurCode))
                                {
                                    TriggerCodes.Add(CurCode);
                                }
                            }
                        }
                        else
                        {
                            if (int.TryParse(RAWItems[1], out CurCode))
                            {
                                TriggerCodes.Add(CurCode);
                            }
                        }
                        break;
                    case "triggerlogageindays":
                        int.TryParse(RAWItems[1], out TriggerLogAgeInDays);
                        break;
                    case "triggerhitpoints":
                        int.TryParse(RAWItems[1], out TriggerHitPoints);
                        break;
                    case "triggeralwaysthisagent":
                        if (RAWItems[1].Contains(","))
                        {
                            var RAWSubitems = RAWItems[1].ToLowerInvariant().Split(',');
                            for (int i2 = 0; i2 < RAWSubitems.Length; i2++)
                            {
                                BlackListedAgents.Add(RAWSubitems[i2]);
                            }
                        }
                        else
                        {
                            BlackListedAgents.Add(RAWItems[1].ToLowerInvariant());
                        }
                        break;
                    case "triggerattransferredsize":
                        long.TryParse(RAWItems[1], out TriggerAtTransferredSize);
                        break;
                    case "triggerattransferredsizeperiod":
                        int.TryParse(RAWItems[1], out TriggerAtTransferredSizePeriod);
                        break;
                    case "websites":
                        if (RAWItems[1].Contains(","))
                        {
                            var RAWSubitems = RAWItems[1].Split(',');
                            for (int i2 = 0; i2 < RAWSubitems.Length; i2++)
                            {
                                Webseites.Add(RAWSubitems[i2]);
                            }
                        }
                        else
                        {
                            Webseites.Add(RAWItems[1]);
                        }
                        break;
                }
                if (TriggerLogAgeInDays > TriggerAtTransferredSizePeriod)
                {
                    MaxLogAge = TriggerLogAgeInDays;
                }
                else
                {
                    MaxLogAge = TriggerAtTransferredSizePeriod;
                }
                if ((TriggerLevel != 0) && (TriggerCodes.Count > 0) && (TriggerLogAgeInDays != 0) && (TriggerHitPoints != 0) && (TriggerAtTransferredSize != 0) && (TriggerAtTransferredSizePeriod != 0))
                {
                    this.Valid = true;
                }
            }
        }
        internal bool Valid { get; set; }
        internal string ConfigPath { get; set; }
        internal string LogPath { get; set; }
        internal string IPTablePath { get; set; }

        internal int TriggerLevel;
        internal HashSet<int> TriggerCodes { get; set; }

        internal int TriggerLogAgeInDays;

        internal int TriggerHitPoints;
        internal HashSet<string> BlackListedAgents { get; set; }

        internal long TriggerAtTransferredSize;

        internal int TriggerAtTransferredSizePeriod;

        internal int MaxLogAge;
        internal HashSet<string> Webseites { get; set; }
    }

    internal sealed class IP
    {
        internal IP(string IPAdress, bool AlreadyBlocked)
        {
            this.IPAdress = IPAdress;
            this.AlreadyBlocked = AlreadyBlocked;
        }
        internal string IPAdress { get; set; }

        internal long ErrorCount;

        internal long TransferredBytes;
        internal bool Blocked { get; set; }
        internal bool AlreadyBlocked { get; set; }
    }
}
