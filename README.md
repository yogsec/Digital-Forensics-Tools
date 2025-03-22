# 🕵️‍♂️ Digital Forensics Tools

![Digital Forensics TOols](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExOG90c3c1YmF3bW8xOWdmaGprdXdtNGVqMDNiNmhpN205OTE1OGdrdiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/44cvOarMUnAfV9oU7A/giphy.gif)

A curated list of essential **digital forensics tools** used for investigation, data recovery, and security analysis. These tools help in disk forensics, memory analysis, network monitoring, malware analysis, and more.

# 🛠 Disk Forensics Tools  

### 🔍 Disk Imaging & Cloning  
- **[Autopsy](https://www.sleuthkit.org/autopsy/)** – GUI-based forensic tool for disk analysis.  
- **[The Sleuth Kit (TSK)](https://www.sleuthkit.org/)** – Command-line toolkit for file system forensics.  
- **[FTK Imager](https://accessdata.com/solutions/digital-forensics/ftk-imager)** – Disk imaging and evidence collection.  
- **[dd (Data Dump)](https://man7.org/linux/man-pages/man1/dd.1.html)** – CLI tool for disk cloning and imaging.  
- **[dcfldd](https://sourceforge.net/projects/dcfldd/)** – Enhanced version of `dd` for forensics.  
- **[Guymager](https://guymager.sourceforge.io/)** – Fast forensic imaging tool with a GUI.  

### 🗂 File System & Partition Analysis  
- **[TestDisk](https://www.cgsecurity.org/wiki/TestDisk)** – Recover lost partitions and repair disk structures.  
- **[PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)** – File recovery from storage media.  
- **[X-Ways Forensics](https://www.x-ways.net/forensics/)** – Advanced disk and file system analysis tool.  
- **[AccessData FTK (Forensic Toolkit)](https://accessdata.com/solutions/digital-forensics/ftk)** – Full forensic investigation suite.  

### 🔎 Metadata & Hash Analysis  
- **[ExifTool](https://exiftool.org/)** – Extract metadata from files.  
- **[md5sum, sha256sum](https://man7.org/linux/man-pages/man1/md5sum.1.html)** – Verify file integrity with hash values.  
- **[Hashdeep](https://github.com/jessek/hashdeep)** – Compute and audit hashes for large datasets.  

### 🧩 File Recovery & Carving  
- **[Foremost](https://foremost.sourceforge.net/)** – Recover deleted files based on headers, footers, and data structures.  
- **[Scalpel](https://github.com/sleuthkit/scalpel)** – File carving tool for deleted file recovery.  
- **[Recuva](https://www.ccleaner.com/recuva)** – User-friendly file recovery software.  

### 🔥 Live Disk Analysis  
- **[Mount Image Pro](https://www.mountimage.com/)** – Mount disk images for live forensic analysis.  
- **[OSForensics](https://www.osforensics.com/)** – Windows-based live forensic analysis tool.  
- **[CAINE (Computer Aided Investigative Environment)](https://www.caine-live.net/)** – Live Linux forensic distro with built-in tools.  

---

# 🧠 Memory Forensics Tools  

### 🔍 Memory Dumping Tools  
- **[DumpIt](https://www.comae.com/)** – One-click RAM dumping tool for Windows.  
- **[WinPmem](https://github.com/Velocidex/WinPmem)** – Windows memory acquisition tool.  
- **[LiME](https://github.com/504ensicsLabs/LiME)** – Extracts live memory from Linux systems.  
- **[AVML](https://github.com/microsoft/avml)** – Memory acquisition for Linux & Azure VMs.  
- **[OSForensics](https://www.osforensics.com/)** – RAM imaging and forensic analysis.  

### 🔬 Memory Analysis Tools  
- **[Volatility](https://github.com/volatilityfoundation/volatility)** – Open-source framework for memory analysis.  
- **[Volatility 3](https://github.com/volatilityfoundation/volatility3)** – Python 3-based version with enhanced support.  
- **[Rekall](https://github.com/google/rekall)** – Memory forensic framework from Google.  
- **[MemProcFS](https://github.com/ufrisk/MemProcFS)** – Mounts memory dumps as a virtual file system.  
- **[Redline](https://www.fireeye.com/services/freeware/redline.html)** – Analyzes memory for malware infections.  

### 🦠 Malware & Process Analysis  
- **[Malfind](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#malfind)** – Detects malicious code injections.  
- **[YARA](https://github.com/VirusTotal/yara)** – Signature-based malware detection in RAM.  
- **[Strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings)** – Extracts readable text from memory dumps.  
- **[PE-sieve](https://github.com/hasherezade/pe-sieve)** – Detects injected malicious code.  
- **[HollowsHunter](https://github.com/hasherezade/hollows_hunter)** – Identifies process hollowing and malware injections.  

### 📊 Memory Timeline & Log Analysis  
- **[Log2Timeline (Plaso)](https://github.com/log2timeline/plaso)** – Creates forensic timelines from memory artifacts.  
- **[Memtriage](https://github.com/SwiftOnSecurity/Memtriage)** – Rapid triage tool for incident response.  
- **[Efilter](https://github.com/google/efilter)** – Query and analyze memory artifacts efficiently.  

---

# 🌐 Network Forensics Tools   

### 🔎 Packet Sniffers & Traffic Analysis  
- **[Wireshark](https://www.wireshark.org/)** – GUI-based packet analyzer for real-time network traffic analysis.  
- **[tcpdump](https://www.tcpdump.org/)** – Command-line packet sniffer for capturing network packets.  
- **[TShark](https://www.wireshark.org/docs/man-pages/tshark.html)** – CLI version of Wireshark for automated packet analysis.  

### 🕵️ Intrusion Detection & Network Security Monitoring  
- **[Zeek (Bro)](https://zeek.org/)** – Network traffic analysis tool for security monitoring.  
- **[Suricata](https://suricata.io/)** – High-performance network IDS, IPS, and NSM tool.  
- **[Snort](https://www.snort.org/)** – Open-source intrusion detection and prevention system (IDS/IPS).  

### 🛠️ Log Analysis & Network Flow Monitoring  
- **[Argus](https://openargus.org/)** – Network flow analysis tool for session data monitoring.  
- **[ELK Stack (Elasticsearch, Logstash, Kibana)](https://www.elastic.co/)** – Log collection and visualization for network logs.  
- **[Splunk](https://www.splunk.com/)** – Advanced log analysis and SIEM for real-time network forensics.  

### 🔓 Deep Packet Inspection & Protocol Analysis  
- **[NetworkMiner](https://www.netresec.com/?page=NetworkMiner)** – Passive network traffic analyzer for extracting forensic data.  
- **[Xplico](https://www.xplico.org/)** – Network forensic tool for reconstructing network sessions.  
- **[NetFlow Analyzer](https://www.manageengine.com/products/netflow/)** – Monitors and analyzes network traffic using NetFlow data.  

### 📡 Wireless Network Forensics  
- **[Kismet](https://www.kismetwireless.net/)** – Wireless network sniffer and intrusion detection tool.  
- **[Aircrack-ng](https://www.aircrack-ng.org/)** – Wi-Fi network security assessment and packet capturing.  
- **[WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple)** – Wireless network penetration testing and monitoring.  

### 🖥️ Man-in-the-Middle (MitM) & Traffic Manipulation  
- **[ettercap](https://www.ettercap-project.org/)** – MitM attack tool for sniffing and network manipulation.  
- **[MITMf](https://github.com/byt3bl33d3r/MITMf)** – Advanced framework for network traffic interception and manipulation.  
- **[Bettercap](https://www.bettercap.org/)** – Swiss army knife for network forensics, pentesting, and MitM attacks.  

### 🏴‍☠️ Darknet & Deep Web Analysis  
- **[Tor](https://www.torproject.org/)** – Anonymity network used for deep web forensics.  
- **[ONIONScan](https://github.com/s-rah/onionscan)** – Deep web analysis and onion service scanning.  

---

## 📱 **Mobile Forensics Tools**  

### 🔍 **Mobile Data Extraction & Analysis**  
- **[Cellebrite UFED](https://cellebrite.com/)** – Industry-standard tool for extracting data from mobile devices.  
- **[Magnet AXIOM](https://www.magnetforensics.com/)** – Mobile forensic analysis and recovery tool.  
- **[Oxygen Forensic Suite](https://www.oxygen-forensic.com/)** – Mobile data extraction, call logs, and app analysis.  
- **[XRY](https://www.msab.com/products/xry/)** – Mobile forensics tool for data extraction and decoding.  
- **[MOBILedit Forensic](https://www.mobiledit.com/forensic)** – Mobile device investigation with logical and physical extraction.  
- **[Belkasoft Evidence Center](https://belkasoft.com/ec)** – Extracts data from iOS, Android, and cloud services.  

### 🔧 **Android Forensics**  
- **[ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb)** – Command-line tool for interacting with Android devices.  
- **[Andriller](https://www.andriller.com/)** – Android pattern lock cracker and data extraction.  
- **[AFLogical](https://github.com/nowsecure/AFLogical)** – Open-source tool for logical data extraction from Android.  
- **[Frida](https://frida.re/)** – Dynamic instrumentation tool for Android reverse engineering.  
- **[Drozer](https://labs.withsecure.com/tools/drozer)** – Security testing framework for Android apps.  
- **[Apktool](https://github.com/iBotPeaches/Apktool)** – Reverse engineer APK files.  

### 🍏 **iOS Forensics**  
- **[iLEAPP (iOS Logs, Events, And Properties Parser)](https://github.com/abrignoni/iLEAPP)** – Extracts logs and artifacts from iOS devices.  
- **[Checkm8 / Checkra1n](https://checkra.in/)** – Jailbreaking tool for forensic extraction.  
- **[Elcomsoft iOS Forensic Toolkit](https://www.elcomsoft.com/eift.html)** – Extracts data from iOS devices, even locked ones.  
- **[iExplorer](https://www.macroplant.com/iexplorer)** – Browse iOS file systems without jailbreaking.  
- **[Cydia Impactor](http://www.cydiaimpactor.com/)** – Install apps and exploit sideloading vulnerabilities.  

### 🌐 **Cloud & Online Data Extraction**  
- **[Oxygen Forensic Cloud Extractor](https://www.oxygen-forensic.com/en/cloud-extractor)** – Extracts mobile data from cloud accounts.  
- **[Google Takeout](https://takeout.google.com/)** – Download data from Google services (Gmail, Drive, etc.).  
- **[iCloudExtractor](https://www.elcomsoft.com/eppb.html)** – Extracts backups from iCloud.  

### 📶 **SIM & IMEI Forensics**  
- **[SIM Cloning Tool](https://github.com/srdja/SIM-Tools)** – Clone and analyze SIM card data.  
- **[Oxygen SIM Detective](https://www.oxygen-forensic.com/en/products/oxygen-forensic-detective)** – Extracts data from SIM cards.  
- **[MOBILedit SIM Clone](https://www.mobiledit.com/sim-clone)** – Copies SIM data and recovers deleted messages.  

### 🔍 **Mobile App & Messaging Analysis**  
- **[WhatsApp Viewer](https://github.com/andreas-mausch/whatsapp-viewer)** – Extracts WhatsApp messages from databases.  
- **[UFED Physical Analyzer](https://www.cellebrite.com/en/ufed-physical-analyzer/)** – Analyzes mobile apps and messaging platforms.  
- **[SQLite Forensic Browser](https://github.com/sqlitebrowser/sqlitebrowser)** – Investigates SQLite databases from apps like WhatsApp and Telegram.  
- **[Paraben E3](https://paraben.com/e3-platform/)** – Extracts and analyzes messages from social media and chat apps.  

---

# 🦠 Malware Forensics Tools  

### 🔍 **1. Static Analysis Tools**  
- **[IDA Pro](https://www.hex-rays.com/)** – Advanced disassembler and decompiler.  
- **[Ghidra](https://ghidra-sre.org/)** – Open-source reverse engineering framework.  
- **[Radare2](https://rada.re/n/)** – Binary analysis and reversing tool.  
- **[PEStudio](https://www.winitor.com/)** – Analyzes Windows executables for malware indicators.  
- **[Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy)** – Detects compiler and packer information.  

### ⚙️ **2. Dynamic Analysis Tools**  
- **[Cuckoo Sandbox](https://cuckoosandbox.org/)** – Automated malware sandbox.  
- **[Any.Run](https://any.run/)** – Interactive cloud-based malware analysis.  
- **[Joe Sandbox](https://www.joesecurity.org/)** – Advanced malware sandboxing.  
- **[FakeNet-NG](https://github.com/fireeye/flare-fakenet-ng)** – Simulates network services to capture malware behavior.  

### 💾 **3. Memory Forensics Tools**  
- **[Volatility](https://github.com/volatilityfoundation/volatility)** – Extracts artifacts from RAM dumps.  
- **[Rekall](https://github.com/google/rekall)** – Memory forensics and incident response.  
- **[RAM Capturer](https://www.magnetforensics.com/)** – Captures live RAM data.  

### 🔗 **4. Malware Behavior Analysis**  
- **[Process Hacker](https://processhacker.sourceforge.io/)** – Monitors and manipulates processes.  
- **[ProcMon (Process Monitor)](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)** – Tracks system activity in real-time.  
- **[Regshot](https://sourceforge.net/projects/regshot/)** – Compares registry snapshots.  
- **[APIMonitor](http://www.rohitab.com/apimonitor)** – Tracks API calls used by malware.  

### 🛠 **5. Code & String Analysis Tools**  
- **[YARA](https://virustotal.github.io/yara/)** – Rule-based malware classification.  
- **[Floss](https://github.com/fireeye/flare-floss)** – Extracts obfuscated strings from malware.  
- **[Binwalk](https://github.com/ReFirmLabs/binwalk)** – Extracts and analyzes firmware.  

### 🌍 **6. Online Malware Analysis Services**  
- **[VirusTotal](https://www.virustotal.com/)** – Multi-engine malware scanning.  
- **[Hybrid Analysis](https://www.hybrid-analysis.com/)** – Free cloud-based malware sandbox.  
- **[MalShare](https://malshare.com/)** – Public malware sample repository.  
- **[URLScan.io](https://urlscan.io/)** – Analyzes suspicious URLs for threats.  

---

# ☁️ Cloud Forensics Tools   

### 🔍 **Cloud Logging & Monitoring**  
- **[AWS CloudTrail](https://aws.amazon.com/cloudtrail/)** – Tracks API activity and security events in AWS.  
- **[AWS GuardDuty](https://aws.amazon.com/guardduty/)** – Threat detection for AWS accounts.  
- **[Google Cloud Logging](https://cloud.google.com/logging/)** – Collects logs from Google Cloud services.  
- **[Azure Monitor](https://azure.microsoft.com/en-us/products/monitor/)** – Tracks Azure activity and performance.  

### 🗂 **Cloud Storage Forensics**  
- **[Google Takeout](https://takeout.google.com/)** – Extracts data from Google accounts (Drive, Gmail, etc.).  
- **[AWS S3 Access Logs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)** – Monitors object access in AWS S3.  
- **[Azure Storage Analytics](https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet)** – Logs Azure Storage activity.  

### 💾 **Cloud Instance & Virtual Machine Forensics**  
- **[Velociraptor](https://www.velociraptor.app/)** – Endpoint forensics and cloud-based threat hunting.  
- **[AWS EC2 Instance Metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)** – Retrieves forensic metadata from AWS instances.  
- **[Google Cloud Compute Disk Snapshots](https://cloud.google.com/compute/docs/disks/create-snapshots)** – Captures VM snapshots for investigation.  
- **[Azure Disk Forensics](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-forensic-best-practices)** – Forensic analysis of Azure virtual disks.  

### 📡 **Cloud Network Traffic Analysis**  
- **[Zeek (Bro)](https://zeek.org/)** – Network monitoring tool for cloud environments.  
- **[AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)** – Captures AWS network traffic.  
- **[Google VPC Flow Logs](https://cloud.google.com/vpc/docs/using-flow-logs)** – Logs network traffic in Google Cloud.  
- **[Azure Network Watcher](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview)** – Monitors traffic flow in Azure.  

### 🔑 **Cloud Identity & Access Forensics**  
- **[AWS IAM Access Analyzer](https://aws.amazon.com/iam/access-analyzer/)** – Analyzes permissions and access control.  
- **[Google Cloud IAM Policy Analyzer](https://cloud.google.com/iam/docs/policy-analyzer)** – Checks permissions and access logs.  
- **[Azure Active Directory Audit Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)** – Tracks identity-related activities.  

### ⚠️ **Cloud Incident Response**  
- **[GRR Rapid Response](https://github.com/google/grr)** – Live forensics for cloud instances.  
- **[AWS Security Hub](https://aws.amazon.com/security-hub/)** – Centralized security alerts for AWS.  
- **[Google Chronicle](https://chronicle.security/)** – Threat intelligence for Google Cloud.  
- **[Azure Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)** – Cloud-native SIEM for security monitoring.  

---

# 📧 Email Forensics Tools  

### 🔍 Email Header Analysis  
- **[MHA (Message Header Analyzer)](https://mha.azurewebsites.net/)** – Online tool to analyze email headers and detect phishing.  
- **[MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx)** – Extract sender IP, SPF, DKIM, and DMARC records.  
- **[Wireshark](https://www.wireshark.org/)** – Packet capture tool for SMTP, IMAP, and POP3 analysis.  

### 📨 Email Metadata Extraction  
- **[EmailTracer](https://github.com/sud0nick/EmailTracer)** – Python tool to extract and analyze email headers.  
- **[ExifTool](https://exiftool.org/)** – Extract metadata from email files (.eml, .msg).  
- **[Xplico](https://www.xplico.org/)** – Extract emails from network traffic captures.  

### 📜 Log & Email File Analysis  
- **[Log2Timeline (Plaso)](https://github.com/log2timeline/plaso)** – Create timelines from email and system logs.  
- **[MailXaminer](https://www.mailxaminer.com/)** – Advanced email forensic investigation tool.  
- **[Forensic Email Collector](https://www.metaspike.com/forensic-email-collector/)** – Extract and analyze cloud-based emails.  

### 🔑 Phishing & Malicious Email Investigation  
- **[PhishTool](https://phishtool.com/)** – Identify phishing attempts from email headers.  
- **[VirusTotal](https://www.virustotal.com/)** – Scan email attachments and URLs for malware.  
- **[YARA](https://virustotal.github.io/yara/)** – Detect patterns in malicious emails and attachments.  

### 🛠️ Email Data Recovery & Conversion  
- **[Mail Viewer](https://www.mitec.cz/mailview.html)** – View and extract data from .eml and .msg files.  
- **[Aid4Mail](https://www.aid4mail.com/)** – Convert, search, and analyze email data.  
- **[Kernel Email Recovery](https://www.nucleustechnologies.com/)** – Recover deleted or corrupted email data.  

---

## 🌟 Let's Connect!

Hello, Hacker! 👋 We'd love to stay connected with you. Reach out to us on any of these platforms and let's build something amazing together:

🌐 **Website:** [https://yogsec.github.io/yogsec/](https://yogsec.github.io/yogsec/)  
📜 **Linktree:** [https://linktr.ee/yogsec](https://linktr.ee/yogsec)  
🔗 **GitHub:** [https://github.com/yogsec](https://github.com/yogsec)  
💼 **LinkedIn (Company):** [https://www.linkedin.com/company/yogsec/](https://www.linkedin.com/company/yogsec/)  
📷 **Instagram:** [https://www.instagram.com/yogsec.io/](https://www.instagram.com/yogsec.io/)  
🐦 **Twitter (X):** [https://x.com/yogsec](https://x.com/yogsec)  
👨‍💼 **Personal LinkedIn:** [https://www.linkedin.com/in/cybersecurity-pentester/](https://www.linkedin.com/in/cybersecurity-pentester/)  
📧 **Email:** abhinavsingwal@gmail.com

---

## ☕ Buy Me a Coffee

☕ **Support Us Here:** [https://buymeacoffee.com/yogsec](https://buymeacoffee.com/yogsec)
