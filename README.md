# 🕵️‍♂️ Digital Forensics Tools  

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

