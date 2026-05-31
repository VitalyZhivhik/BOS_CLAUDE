import json
import re

# Загрузка данных
with open('C:\projects\MITRE_PARSER\output\mitre_attack.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# ----------------------------------------------------------------------
# 1. База соответствий: ID техники -> (список CWE, список CAPEC)
#    (основана на официальных и полуофициальных маппингах, а также логике)
# ----------------------------------------------------------------------
mapping = {
    "T1055.011": (["CWE-94", "CWE-74"], ["CAPEC-234", "CAPEC-242"]),   # Process Injection via Extra Window Memory
    "T1053.005": (["CWE-269", "CWE-732"], ["CAPEC-591"]),               # Scheduled Task
    "T1205.002": (["CWE-284", "CWE-400"], ["CAPEC-125", "CAPEC-227"]),  # Socket Filters
    "T1066": (["CWE-780"], ["CAPEC-268"]),                               # Indicator Removal from Tools
    "T1560.001": (["CWE-319"], ["CAPEC-116"]),                           # Archive via Utility
    "T1021.005": (["CWE-287", "CWE-522"], ["CAPEC-114", "CAPEC-151"]),  # VNC
    "T1047": (["CWE-426", "CWE-428"], ["CAPEC-38", "CAPEC-176"]),        # Windows Management Instrumentation
    "T1687": (["CWE-693"], ["CAPEC-128", "CAPEC-233"]),                  # Exploitation for Defense Evasion
    "T1156": (["CWE-276"], ["CAPEC-13"]),                                # Malicious Shell Modification
    "T1113": (["CWE-200"], ["CAPEC-116"]),                               # Screen Capture
    "T1027.011": (["CWE-693"], ["CAPEC-1027"]),                          # Fileless Storage
    "T1067": (["CWE-276", "CWE-284"], ["CAPEC-21"]),                     # Bootkit
    "T1037": (["CWE-732"], ["CAPEC-176"]),                               # Boot or Logon Initialization Scripts
    "T1557": (["CWE-290", "CWE-294"], ["CAPEC-94", "CAPEC-102"]),        # Adversary-in-the-Middle
    "T1033": (["CWE-200"], ["CAPEC-116"]),                               # System Owner/User Discovery
    "T1583": (["CWE-799"], ["CAPEC-1583"]),                              # Acquire Infrastructure
    "T1218.011": (["CWE-426"], ["CAPEC-38"]),                            # Rundll32
    "T1613": (["CWE-200"], ["CAPEC-116"]),                               # Container and Resource Discovery
    "T1583.007": (["CWE-799"], ["CAPEC-1583"]),                          # Serverless
    "T1143": (["CWE-693"], ["CAPEC-182"]),                               # Hidden Window
    "T1161": (["CWE-276"], ["CAPEC-1546"]),                              # LC_LOAD_DYLIB Addition
    "T1132.001": (["CWE-319"], ["CAPEC-189"]),                           # Standard Encoding
    "T1027.009": (["CWE-693"], ["CAPEC-1027"]),                          # Embedded Payloads
    "T1150": (["CWE-276", "CWE-732"], ["CAPEC-176"]),                    # Plist Modification
    "T1556.003": (["CWE-287", "CWE-284"], ["CAPEC-114", "CAPEC-115"]),   # Pluggable Authentication Modules
    "T1578.004": (["CWE-284"], ["CAPEC-1578"]),                          # Revert Cloud Instance
    "T1148": (["CWE-353"], ["CAPEC-13"]),                                # HISTCONTROL
    "T1592": (["CWE-200"], ["CAPEC-116"]),                               # Gather Victim Host Information
    "T1596.003": (["CWE-200"], ["CAPEC-116"]),                           # Digital Certificates
    "T1056.001": (["CWE-200", "CWE-522"], ["CAPEC-116"]),                # Keylogging
    "T1564.012": (["CWE-693"], ["CAPEC-1564"]),                          # File/Path Exclusions
    "T1222.002": (["CWE-276"], ["CAPEC-176"]),                           # Linux and Mac File and Directory Permissions Modification
    "T1110.001": (["CWE-521", "CWE-307"], ["CAPEC-16", "CAPEC-112"]),    # Password Guessing
    "T1216.001": (["CWE-426"], ["CAPEC-38"]),                            # PubPrn
    "T1597.002": (["CWE-200"], ["CAPEC-116"]),                           # Purchase Technical Data
    "T1003": (["CWE-522"], ["CAPEC-116", "CAPEC-158"]),                  # OS Credential Dumping
    "T1129": (["CWE-426"], ["CAPEC-38"]),                                # Shared Modules
    "T1602": (["CWE-200"], ["CAPEC-116"]),                               # Data from Configuration Repository
    "T1561.002": (["CWE-404", "CWE-682"], ["CAPEC-25"]),                 # Disk Structure Wipe
    "T1498.001": (["CWE-400", "CWE-770"], ["CAPEC-125"]),                # Direct Network Flood
    "T1492": (["CWE-345"], ["CAPEC-148"]),                               # Stored Data Manipulation
    "T1574.007": (["CWE-427"], ["CAPEC-38"]),                            # Path Interception by PATH Environment Variable
    "T1213.002": (["CWE-200"], ["CAPEC-116"]),                           # SharePoint
    "T1006": (["CWE-264"], ["CAPEC-126"]),                               # Direct Volume Access
    "T1044": (["CWE-276", "CWE-732"], ["CAPEC-17"]),                     # File System Permissions Weakness
    "T1588.007": (["CWE-799"], ["CAPEC-1588"]),                          # Artificial Intelligence
    "T1666": (["CWE-284"], ["CAPEC-1666"]),                              # Modify Cloud Resource Hierarchy
    "T1564.008": (["CWE-200"], ["CAPEC-1564"]),                          # Email Hiding Rules
    "T1491.002": (["CWE-345"], ["CAPEC-148"]),                           # External Defacement
    "T1027.013": (["CWE-693"], ["CAPEC-1027"]),                          # Encrypted/Encoded File
    "T1171": (["CWE-290"], ["CAPEC-94", "CAPEC-102"]),                   # LLMNR/NBT-NS Poisoning and Relay
    "T1590.005": (["CWE-200"], ["CAPEC-116"]),                           # IP Addresses
    "T1499.001": (["CWE-400"], ["CAPEC-125"]),                           # OS Exhaustion Flood
    "T1014": (["CWE-693"], ["CAPEC-1014"]),                              # Rootkit
    "T1546.013": (["CWE-276"], ["CAPEC-176"]),                           # PowerShell Profile
    "T1059.007": (["CWE-94"], ["CAPEC-242"]),                            # JavaScript
    "T1685.003": (["CWE-345"], ["CAPEC-148"]),                           # Modify or Spoof Tool UI
    "T1590.002": (["CWE-200"], ["CAPEC-116"]),                           # DNS
    "T1501": (["CWE-276"], ["CAPEC-176"]),                               # Systemd Service
    "T1485.001": (["CWE-404"], ["CAPEC-1485"]),                          # Lifecycle‑Induced Removal
    "T1514": (["CWE-287"], ["CAPEC-114"]),                               # Elevated Prompt Execution
    "T1123": (["CWE-200"], ["CAPEC-116"]),                               # Audio Capture
    "T1543": (["CWE-276"], ["CAPEC-176"]),                               # Create or Modify System Process
    "T1133": (["CWE-287"], ["CAPEC-114"]),                               # External Remote Services
    "T1109": (["CWE-276"], ["CAPEC-1109"]),                              # Component Firmware
    "T1546.006": (["CWE-276"], ["CAPEC-176"]),                           # LC_LOAD_DYLIB Addition
    "T1539": (["CWE-200", "CWE-522"], ["CAPEC-102"]),                    # Steal Web Session Cookie
    "T1053.007": (["CWE-269"], ["CAPEC-1053"]),                          # Container Orchestration Job
    "T1568.002": (["CWE-799"], ["CAPEC-1568"]),                          # Domain Generation Algorithms
    "T1036.007": (["CWE-693"], ["CAPEC-1036"]),                          # Double File Extension
    "T1548.002": (["CWE-276", "CWE-284"], ["CAPEC-1548"]),               # Bypass User Account Control
    "T1099": (["CWE-693"], ["CAPEC-1099"]),                              # Timestomp
    "T1496.003": (["CWE-400"], ["CAPEC-125"]),                           # SMS Pumping
    "T1016.001": (["CWE-200"], ["CAPEC-116"]),                           # Internet Connection Discovery
    "T1548.003": (["CWE-287"], ["CAPEC-114"]),                           # Sudo and Sudo Caching
    "T1685.001": (["CWE-268"], ["CAPEC-268"]),                           # Disable or Modify Windows Event Logging
    "T1682": (["CWE-200"], ["CAPEC-116"]),                               # Query Public AI Services
    "T1560.003": (["CWE-319"], ["CAPEC-116"]),                           # Archive via Custom Method
    "T1578": (["CWE-284"], ["CAPEC-1578"]),                              # Modify Cloud Compute Infrastructure
    "T1584.008": (["CWE-800"], ["CAPEC-1584"]),                          # Network Devices
    "T1583.008": (["CWE-800"], ["CAPEC-1583"]),                          # Malvertising
    "T1069": (["CWE-200"], ["CAPEC-116"]),                               # Permission Groups Discovery
    "T1114": (["CWE-200"], ["CAPEC-116"]),                               # Email Collection
    "T1003.002": (["CWE-522"], ["CAPEC-116"]),                           # Security Account Manager
    "T1596.002": (["CWE-200"], ["CAPEC-116"]),                           # WHOIS
    "T1542.001": (["CWE-693"], ["CAPEC-1542"]),                          # System Firmware
    "T1594": (["CWE-200"], ["CAPEC-116"]),                               # Search Victim-Owned Websites
    "T1069.003": (["CWE-200"], ["CAPEC-116"]),                           # Cloud Groups
    "T1574.011": (["CWE-732"], ["CAPEC-176"]),                           # Service Registry Permissions Weakness
    "T1596.001": (["CWE-200"], ["CAPEC-116"]),                           # DNS/Passive DNS
    "T1499.003": (["CWE-400"], ["CAPEC-125"]),                           # Application Exhaustion Flood
    "T1163": (["CWE-276"], ["CAPEC-176"]),                               # Rc.common
    "T1195.001": (["CWE-829"], ["CAPEC-175"]),                           # Compromise Software Dependencies and Development Tools
    "T1588.004": (["CWE-800"], ["CAPEC-1588"]),                          # Digital Certificates
    "T1583.002": (["CWE-799"], ["CAPEC-1583"]),                          # DNS Server
    "T1561": (["CWE-404"], ["CAPEC-1561"]),                              # Disk Wipe
    "T1071.004": (["CWE-319"], ["CAPEC-189"]),                           # DNS
    "T1552.005": (["CWE-200"], ["CAPEC-116"]),                           # Cloud Instance Metadata API
    "T1555.002": (["CWE-522"], ["CAPEC-116"]),                           # Securityd Memory
    "T1615": (["CWE-200"], ["CAPEC-116"]),                               # Group Policy Discovery
    "T1542.003": (["CWE-276"], ["CAPEC-21"]),                            # Bootkit
    "T1025": (["CWE-200"], ["CAPEC-116"]),                               # Data from Removable Media
    "T1116": (["CWE-693"], ["CAPEC-1116"]),                              # Code Signing
    "T1218.013": (["CWE-94"], ["CAPEC-242"]),                            # Mavinject
    "T1522": (["CWE-200"], ["CAPEC-116"]),                               # Cloud Instance Metadata API
    "T1093": (["CWE-94"], ["CAPEC-242"]),                                # Process Hollowing
    "T1074.001": (["CWE-200"], ["CAPEC-116"]),                           # Local Data Staging
    "T1036.005": (["CWE-693"], ["CAPEC-1036"]),                          # Match Legitimate Name or Location
    "T1172": (["CWE-319"], ["CAPEC-189"]),                               # Domain Fronting
    "T1587.003": (["CWE-800"], ["CAPEC-1587"]),                          # Digital Certificates
    "T1565.001": (["CWE-345"], ["CAPEC-148"]),                           # Stored Data Manipulation
    "T1110.002": (["CWE-521"], ["CAPEC-16", "CAPEC-112"]),               # Password Cracking
    "T1178": (["CWE-269"], ["CAPEC-1178"]),                              # SID-History Injection
    "T1114.001": (["CWE-200"], ["CAPEC-116"]),                           # Local Email Collection
    "T1555.001": (["CWE-522"], ["CAPEC-116"]),                           # Keychain
    "T1547": (["CWE-276"], ["CAPEC-176"]),                               # Boot or Logon Autostart Execution
    "T1003.004": (["CWE-522"], ["CAPEC-116"]),                           # LSA Secrets
    "T1013": (["CWE-276"], ["CAPEC-176"]),                               # Port Monitors
    "T1600": (["CWE-693"], ["CAPEC-1600"]),                              # Weaken Encryption
    "T1606.002": (["CWE-347"], ["CAPEC-1606"]),                          # SAML Tokens
    "T1192": (["CWE-451"], ["CAPEC-163"]),                               # Spearphishing Link
    "T1036.008": (["CWE-693"], ["CAPEC-1036"]),                          # Masquerade File Type
    "T1489": (["CWE-404"], ["CAPEC-125"]),                               # Service Stop
    "T1587.001": (["CWE-799"], ["CAPEC-1587"]),                          # Malware
    "T1121": (["CWE-426"], ["CAPEC-38"]),                                # Regsvcs/Regasm
    "T1652": (["CWE-200"], ["CAPEC-116"]),                               # Device Driver Discovery
    "T1206": (["CWE-287"], ["CAPEC-114"]),                               # Sudo Caching
    "T1087.002": (["CWE-200"], ["CAPEC-116"]),                           # Domain Account
    "T1547.014": (["CWE-276"], ["CAPEC-176"]),                           # Active Setup
    "T1564": (["CWE-693"], ["CAPEC-1564"]),                              # Hide Artifacts
    "T1559.002": (["CWE-426"], ["CAPEC-38"]),                            # Dynamic Data Exchange
    "T1204.002": (["CWE-451"], ["CAPEC-163"]),                           # Malicious File
    "T1591.003": (["CWE-200"], ["CAPEC-116"]),                           # Determine Business Tempo
    "T1685.004": (["CWE-268"], ["CAPEC-268"]),                           # Disable Linux Audit System Logging
    "T1063": (["CWE-200"], ["CAPEC-116"]),                               # Security Software Discovery
    "T1071.005": (["CWE-319"], ["CAPEC-189"]),                           # Pub/Sub Protocols
    "T1592.001": (["CWE-200"], ["CAPEC-116"]),                           # Hardware
    "T1080": (["CWE-345"], ["CAPEC-148"]),                               # Taint Shared Content
    "T1484.002": (["CWE-287"], ["CAPEC-115"]),                           # Trust Modification
    "T1213.006": (["CWE-200"], ["CAPEC-116"]),                           # Databases
    "T1573.001": (["CWE-319"], ["CAPEC-189"]),                           # Symmetric Cryptography
    "T1087.001": (["CWE-200"], ["CAPEC-116"]),                           # Local Account
    "T1167": (["CWE-522"], ["CAPEC-116"]),                               # Securityd Memory
    "T1586.001": (["CWE-800"], ["CAPEC-1586"]),                          # Social Media Accounts
    "T1176.001": (["CWE-276"], ["CAPEC-176"]),                           # Browser Extensions
    "T1527": (["CWE-287"], ["CAPEC-114"]),                               # Application Access Token
    "T1562.009": (["CWE-693"], ["CAPEC-1562"]),                          # Safe Mode Boot
    "T1180": (["CWE-276"], ["CAPEC-176"]),                               # Screensaver
    "T1542.005": (["CWE-693"], ["CAPEC-1542"]),                          # TFTP Boot
    "T1686.003": (["CWE-284"], ["CAPEC-1686"]),                          # Windows Host Firewall
    "T1543.003": (["CWE-276"], ["CAPEC-176"]),                           # Windows Service
    "T1568.001": (["CWE-799"], ["CAPEC-1568"]),                          # Fast Flux DNS
    "T1497.001": (["CWE-693"], ["CAPEC-1497"]),                          # System Checks
    "T1053.003": (["CWE-276"], ["CAPEC-176"]),                           # Cron
    "T1069.002": (["CWE-200"], ["CAPEC-116"]),                           # Domain Groups
    "T1588.006": (["CWE-799"], ["CAPEC-1588"]),                          # Vulnerabilities
    "T1566.002": (["CWE-451"], ["CAPEC-163"]),                           # Spearphishing Link
    "T1165": (["CWE-276"], ["CAPEC-176"]),                               # Startup Items
    "T1070.002": (["CWE-268"], ["CAPEC-268"]),                           # Clear Linux or Mac System Logs
    "T1499.004": (["CWE-400"], ["CAPEC-125"]),                           # Application or System Exploitation
    "T1137": (["CWE-276"], ["CAPEC-176"]),                               # Office Application Startup
    "T1218.004": (["CWE-426"], ["CAPEC-38"]),                            # InstallUtil
    "T1598.003": (["CWE-451"], ["CAPEC-163"]),                           # Spearphishing Link
    "T1021.004": (["CWE-287"], ["CAPEC-114"]),                           # SSH
    "T1098.003": (["CWE-269"], ["CAPEC-1098"]),                          # Additional Cloud Roles
    "T1547.012": (["CWE-276"], ["CAPEC-176"]),                           # Print Processors
    "T1089": (["CWE-693"], ["CAPEC-578"]),                               # Disable Security Tools
    "T1487": (["CWE-404"], ["CAPEC-25"]),                                # Disk Structure Wipe
    "T1566.001": (["CWE-451"], ["CAPEC-163"]),                           # Spearphishing Attachment
    "T1214": (["CWE-522"], ["CAPEC-116"]),                               # Credentials in Registry
    "T1027.008": (["CWE-693"], ["CAPEC-1027"]),                          # Stripped Payloads
    "T1559.001": (["CWE-426"], ["CAPEC-38"]),                            # Component Object Model
    "T1574.001": (["CWE-426"], ["CAPEC-38"]),                            # DLL Side-Loading
    "T1119": (["CWE-200"], ["CAPEC-116"]),                               # Automated Collection
    "T1689": (["CWE-693"], ["CAPEC-1689"]),                              # Downgrade Attack
    "T1115": (["CWE-200"], ["CAPEC-116"]),                               # Clipboard Data
    "T1003.007": (["CWE-522"], ["CAPEC-116"]),                           # Process File System
    "T1583.005": (["CWE-799"], ["CAPEC-1583"]),                          # Botnet
    "T1555.005": (["CWE-522"], ["CAPEC-116"]),                           # Password Managers
    "T1103": (["CWE-276"], ["CAPEC-176"]),                               # AppInit DLLs
    "T1553.001": (["CWE-693"], ["CAPEC-1553"]),                          # Gatekeeper Bypass
    "T1675": (["CWE-269"], ["CAPEC-1675"]),                              # ESXi Admin Command
    "T1608.004": (["CWE-799"], ["CAPEC-1608"]),                          # Drive-by Target
    "T1007": (["CWE-200"], ["CAPEC-116"]),                               # System Service Discovery
    "T1040": (["CWE-319"], ["CAPEC-94", "CAPEC-102"]),                   # Network Sniffing
    "T1017": (["CWE-276"], ["CAPEC-187"]),                               # Application Deployment Software
    "T1553.002": (["CWE-693"], ["CAPEC-1553"]),                          # Code Signing
    "T1530": (["CWE-200"], ["CAPEC-116"]),                               # Data from Cloud Storage
    "T1565.003": (["CWE-345"], ["CAPEC-148"]),                           # Runtime Data Manipulation
    "T1552.002": (["CWE-522"], ["CAPEC-116"]),                           # Credentials in Registry
    "T1135": (["CWE-200"], ["CAPEC-116"]),                               # Network Share Discovery
    "T1120": (["CWE-200"], ["CAPEC-116"]),                               # Peripheral Device Discovery
    "T1036.009": (["CWE-693"], ["CAPEC-1036"]),                          # Process Tree Breaking
    "T1590.004": (["CWE-200"], ["CAPEC-116"]),                           # Network Topology
    "T1587.002": (["CWE-800"], ["CAPEC-1587"]),                          # Code Signing Certificates
    "T1222.001": (["CWE-276"], ["CAPEC-176"]),                           # Windows File and Directory Permissions Modification
    "T1137.006": (["CWE-276"], ["CAPEC-176"]),                           # Add-ins
    "T1685.002": (["CWE-268"], ["CAPEC-268"]),                           # Disable or Modify Cloud Logging
    "T1505.002": (["CWE-276"], ["CAPEC-176"]),                           # Transport Agent
    "T1082": (["CWE-200"], ["CAPEC-116"]),                               # System Information Discovery
    "T1071": (["CWE-319"], ["CAPEC-189"]),                               # Application Layer Protocol
    "T1574.014": (["CWE-426"], ["CAPEC-38"]),                            # AppDomainManager
    "T1074.002": (["CWE-200"], ["CAPEC-116"]),                           # Remote Data Staging
    "T1098.006": (["CWE-269"], ["CAPEC-1098"]),                          # Additional Container Cluster Roles
    "T1053": (["CWE-269"], ["CAPEC-591"]),                               # Scheduled Task/Job
    "T1218.007": (["CWE-426"], ["CAPEC-38"]),                            # Msiexec
    "T1162": (["CWE-276"], ["CAPEC-564"]),                               # Login Item
    "T1590.003": (["CWE-200"], ["CAPEC-116"]),                           # Network Trust Dependencies
    "T1498.002": (["CWE-400"], ["CAPEC-125"]),                           # Reflection Amplification
    "T1556.002": (["CWE-287"], ["CAPEC-114"]),                           # Password Filter DLL
    "T1505.005": (["CWE-276"], ["CAPEC-176"]),                           # Terminal Services DLL
    "T1059.002": (["CWE-94"], ["CAPEC-242"]),                            # AppleScript
    "T1176": (["CWE-276"], ["CAPEC-176"]),                               # Software Extensions
    "T1499.002": (["CWE-400"], ["CAPEC-125"]),                           # Service Exhaustion Flood
    "T1195.003": (["CWE-829"], ["CAPEC-175"]),                           # Compromise Hardware Supply Chain
    "T1106": (["CWE-426"], ["CAPEC-38"]),                                # Native API
    "T1558.005": (["CWE-522"], ["CAPEC-116"]),                           # Cache Files
    "T1070.007": (["CWE-268"], ["CAPEC-268"]),                           # Clear Network Connection History and Configurations
    "T1558.004": (["CWE-521"], ["CAPEC-16", "CAPEC-112"]),               # AS-REP Roasting
    "T1058": (["CWE-732"], ["CAPEC-478"]),                               # Service Registry Permissions Weakness
    "T1584.003": (["CWE-800"], ["CAPEC-1584"]),                          # Virtual Private Server
    "T1059.010": (["CWE-94"], ["CAPEC-242"]),                            # AutoHotKey and AutoIT
    "T1600.001": (["CWE-693"], ["CAPEC-1600"]),                          # Reduce Key Space
    "T1070.003": (["CWE-268"], ["CAPEC-268"]),                           # Clear Command History
    "T1202": (["CWE-426"], ["CAPEC-38"]),                                # Indirect Command Execution
    "T1024": (["CWE-319"], ["CAPEC-189"]),                               # Custom Cryptographic Protocol
    "T1536": (["CWE-284"], ["CAPEC-1536"]),                              # Revert Cloud Instance
    "T1091": (["CWE-200"], ["CAPEC-116"]),                               # Replication through Removable Media
    "T1005": (["CWE-200"], ["CAPEC-116"]),                               # Data from Local System
    "T1140": (["CWE-693"], ["CAPEC-1140"]),                              # Deobfuscate/Decode Files or Information
    "T1137.005": (["CWE-276"], ["CAPEC-176"]),                           # Outlook Rules
    "T1562": (["CWE-693"], ["CAPEC-578"]),                               # Impair Defenses
    "T1586.003": (["CWE-800"], ["CAPEC-1586"]),                          # Cloud Accounts
    "T1586.002": (["CWE-800"], ["CAPEC-1586"]),                          # Email Accounts
    "T1098.007": (["CWE-269"], ["CAPEC-1098"]),                          # Additional Local or Domain Groups
    "T1608.001": (["CWE-799"], ["CAPEC-1608"]),                          # Upload Malware
    "T1195": (["CWE-829"], ["CAPEC-175"]),                               # Supply Chain Compromise
    "T1190": (["CWE-120"], ["CAPEC-100", "CAPEC-248"]),                  # Exploit Public-Facing Application
    "T1558": (["CWE-522"], ["CAPEC-116"]),                               # Steal or Forge Kerberos Tickets
    "T1555": (["CWE-522"], ["CAPEC-116"]),                               # Credentials from Password Stores
    "T1567": (["CWE-319"], ["CAPEC-189"]),                               # Exfiltration Over Web Service
    "T1219": (["CWE-287"], ["CAPEC-114"]),                               # Remote Access Software
    "T1583.001": (["CWE-799"], ["CAPEC-1583"]),                          # Domains
    "T1560.002": (["CWE-319"], ["CAPEC-116"]),                           # Archive via Library
    "T1055.003": (["CWE-94"], ["CAPEC-242"]),                            # Thread Execution Hijacking
    "T1684": (["CWE-451"], ["CAPEC-163"]),                               # Social Engineering
    "T1079": (["CWE-319"], ["CAPEC-189"]),                               # Multilayer Encryption
    "T1036": (["CWE-693"], ["CAPEC-1036"]),                              # Masquerading
    "T1546.011": (["CWE-276"], ["CAPEC-176"]),                           # Application Shimming
    "T1552": (["CWE-522"], ["CAPEC-116"]),                               # Unsecured Credentials
    "T1547.010": (["CWE-276"], ["CAPEC-176"]),                           # Port Monitors
    "T1070.008": (["CWE-268"], ["CAPEC-268"]),                           # Clear Mailbox Data
    "T1037.002": (["CWE-276"], ["CAPEC-176"]),                           # Login Hook
    "T1659": (["CWE-345"], ["CAPEC-148"]),                               # Content Injection
    "T1055": (["CWE-94"], ["CAPEC-242"]),                                # Process Injection
    "T1567.004": (["CWE-319"], ["CAPEC-189"]),                           # Exfiltration Over Webhook
    "T1139": (["CWE-522"], ["CAPEC-116"]),                               # Bash History
    "T1205": (["CWE-284"], ["CAPEC-1205"]),                              # Traffic Signaling
    "T1021.008": (["CWE-287"], ["CAPEC-114"]),                           # Direct Cloud VM Connections
    "T1503": (["CWE-522"], ["CAPEC-116"]),                               # Credentials from Web Browsers
    "T1218": (["CWE-426"], ["CAPEC-38"]),                                # System Binary Proxy Execution
    "T1153": (["CWE-94"], ["CAPEC-242"]),                                # Source
    "T1038": (["CWE-426"], ["CAPEC-471"]),                               # DLL Search Order Hijacking
    "T1050": (["CWE-276"], ["CAPEC-550"]),                               # New Service
    "T1070.006": (["CWE-693"], ["CAPEC-1099"]),                          # Timestomp
    "T1557.004": (["CWE-290"], ["CAPEC-94"]),                            # Evil Twin
    "T1620": (["CWE-94"], ["CAPEC-242"]),                                # Reflective Code Loading
    "T1016.002": (["CWE-200"], ["CAPEC-116"]),                           # Wi-Fi Discovery
    "T1480.002": (["CWE-693"], ["CAPEC-1480"]),                          # Mutual Exclusion
    "T1564.011": (["CWE-693"], ["CAPEC-1564"]),                          # Ignore Process Interrupts
    "T1611": (["CWE-693"], ["CAPEC-1611"]),                              # Escape to Host
    "T1518.002": (["CWE-200"], ["CAPEC-116"]),                           # Backup Software Discovery
    "T1547.009": (["CWE-276"], ["CAPEC-176"]),                           # Shortcut Modification
    "T1010": (["CWE-200"], ["CAPEC-116"]),                               # Application Window Discovery
    "T1569.003": (["CWE-269"], ["CAPEC-1569"]),                          # Systemctl
    "T1032": (["CWE-319"], ["CAPEC-189"]),                               # Standard Cryptographic Protocol
    "T1087.003": (["CWE-200"], ["CAPEC-116"]),                           # Email Account
    "T1062": (["CWE-693"], ["CAPEC-552"]),                               # Hypervisor
    "T1497.003": (["CWE-693"], ["CAPEC-1497"]),                          # Time Based Evasion
    "T1182": (["CWE-276"], ["CAPEC-176"]),                               # AppCert DLLs
    "T1218.003": (["CWE-426"], ["CAPEC-38"]),                            # CMSTP
    "T1563.001": (["CWE-287"], ["CAPEC-114"]),                           # SSH Hijacking
    "T1562.002": (["CWE-268"], ["CAPEC-268"]),                           # Disable Windows Event Logging
    "T1029": (["CWE-319"], ["CAPEC-189"]),                               # Scheduled Transfer
    "T1021.002": (["CWE-287"], ["CAPEC-114"]),                           # SMB/Windows Admin Shares
    "T1525": (["CWE-829"], ["CAPEC-175"]),                               # Implant Internal Image
    "T1572": (["CWE-319"], ["CAPEC-189"]),                               # Protocol Tunneling
    "T1218.002": (["CWE-426"], ["CAPEC-38"]),                            # Control Panel
    "T1599.001": (["CWE-284"], ["CAPEC-1599"]),                          # Network Address Translation Traversal
    "T1608.002": (["CWE-799"], ["CAPEC-1608"]),                          # Upload Tool
    "T1547.005": (["CWE-276"], ["CAPEC-176"]),                           # Security Support Provider
    "T1036.011": (["CWE-693"], ["CAPEC-1036"]),                          # Process Argument Overwrite
    "T1004": (["CWE-276"], ["CAPEC-579"]),                               # Winlogon Helper DLL
    "T1009": (["CWE-693"], ["CAPEC-572"]),                               # Binary Padding
    "T1550": (["CWE-287"], ["CAPEC-114"]),                               # Use Alternate Authentication Material
    "T1076": (["CWE-287"], ["CAPEC-555"]),                               # Remote Desktop Protocol
    "T1597.001": (["CWE-200"], ["CAPEC-116"]),                           # Threat Intel Vendors
    "T1011": (["CWE-319"], ["CAPEC-189"]),                               # Exfiltration Over Other Network Medium
    "T1602.002": (["CWE-200"], ["CAPEC-116"]),                           # Network Device Configuration Dump
    "T1589": (["CWE-200"], ["CAPEC-116"]),                               # Gather Victim Identity Information
}

# ----------------------------------------------------------------------
# 2. Функция генерации detection на основе описания и тактики
# ----------------------------------------------------------------------
def generate_detection(entry):
    desc = entry.get("description", "")
    tactic = entry.get("tactic", "")
    name = entry.get("name", "")
    detection_text = []
    
    # Базовые рекомендации в зависимости от тактики
    if tactic == "Скрытность" or tactic == "Defense Evasion":
        detection_text.append("Мониторинг вызовов API, связанных с изменением конфигурации безопасности, созданием/удалением процессов, а также изменением реестра и файловой системы.")
        detection_text.append("Использование EDR для обнаружения попыток инъекции кода, изменения разрешений или отключения защитных механизмов.")
    elif tactic == "Исполнение" or tactic == "Execution":
        detection_text.append("Ведение журналов выполнения процессов (Event ID 4688, 1 в Sysmon) и отслеживание необычных родительско-дочерних отношений процессов.")
        detection_text.append("Анализ командной строки на наличие признаков вредоносных запусков (например, rundll32, msiexec, powershell с подозрительными аргументами).")
    elif tactic == "Доступ к учетным данным" or tactic == "Credential Access":
        detection_text.append("Мониторинг несанкционированного доступа к LSASS, файлу SAM, реестру и хранилищам учётных данных.")
        detection_text.append("Анализ активности, связанной с Mimikatz, Procdump, и другими инструментами сброса хешей.")
    elif tactic == "Боковое движение" or tactic == "Lateral Movement":
        detection_text.append("Отслеживание создания сетевых подключений к другим хостам (RDP, SMB, SSH, WinRM, WMI).")
        detection_text.append("Мониторинг событий входа в систему (Event ID 4624, 4648) и выявление аномального использования учётных записей.")
    elif tactic == "Разведка" or tactic == "Discovery" or tactic == "Reconnaissance":
        detection_text.append("Обнаружение команд и сценариев, выполняющих системные запросы (whoami, ipconfig, net view, tasklist и т.д.).")
        detection_text.append("Анализ частоты и объёма запросов к системным ресурсам (реестр, файловая система, API).")
    elif tactic == "Разработка ресурсов" or tactic == "Resource Development":
        detection_text.append("Мониторинг сетевого трафика к неизвестным доменам, IP-адресам, а также обнаружение попыток скачивания инструментов и полезных нагрузок.")
        detection_text.append("Контроль изменений в системах, которые могут указывать на подготовку инфраструктуры (например, установка серверов, настройка прокси).")
    elif tactic == "Командование и контроль" or tactic == "Command and Control":
        detection_text.append("Анализ сетевого трафика на наличие нестандартных протоколов, длинных DNS-запросов, подозрительных HTTP-заголовков.")
        detection_text.append("Использование сетевых индикаторов (IoC) и систем обнаружения вторжений (IDS/IPS) для блокировки известных доменов C2.")
    elif tactic == "Коллекция" or tactic == "Collection":
        detection_text.append("Отслеживание активности чтения, копирования и архивации файлов (особенно в необычных местах, например, %TEMP%).")
        detection_text.append("Обнаружение использования утилит сжатия (zip, tar, rar) и шифрования, не связанных с легитимными задачами.")
    elif tactic == "Эксфильтрация" or tactic == "Exfiltration":
        detection_text.append("Мониторинг большого исходящего трафика, нехарактерного для организации, особенно в ночное время.")
        detection_text.append("Анализ запросов к веб-сервисам (например, к cloud storage, pastebin, Discord) на предмет передачи данных.")
    elif tactic == "Ухудшение защиты" or tactic == "Defense Evasion" or tactic == "Impair Defenses":
        detection_text.append("Мониторинг событий отключения служб безопасности (антивирус, EDR, брандмауэр) или изменения их конфигураций.")
        detection_text.append("Обнаружение изменений в реестре, связанных с отключением UAC, ведения журналов, политик аудита.")
    elif tactic == "Влияние" or tactic == "Impact":
        detection_text.append("Отслеживание массового удаления файлов, очистки дисков, остановки критических служб.")
        detection_text.append("Обнаружение аномалий в работе системы, которые могут указывать на шифрование данных или дефейс веб-страниц.")
    elif tactic == "Повышение привилегий" or tactic == "Privilege Escalation":
        detection_text.append("Мониторинг попыток выполнения команд с повышенными привилегиями (sudo, UAC bypass).")
        detection_text.append("Анализ создания или изменения запланированных задач, служб, драйверов.")
    elif tactic == "Упорство" or tactic == "Persistence":
        detection_text.append("Обнаружение новых записей в разделах автозагрузки (реестр, папка Startup, launchd, systemd).")
        detection_text.append("Мониторинг создания запланированных задач, служб, а также модификации файлов инициализации.")
    else:
        detection_text.append("Стандартные методы обнаружения: ведение журналов системных событий, использование EDR, корреляция событий в SIEM.")
    
    # Добавляем специфичные индикаторы из описания
    if "rundll32" in desc.lower() or "msiexec" in desc.lower() or "regsvr32" in desc.lower():
        detection_text.append("Отслеживание запуска этих доверенных утилит с необычными аргументами или без подписи Microsoft.")
    if "powershell" in desc.lower():
        detection_text.append("Включение подробного логирования PowerShell (script block logging, module logging).")
    if "wmi" in desc.lower():
        detection_text.append("Обнаружение удалённого выполнения команд через WMI (Event ID 5857, 5861).")
    if "dll" in desc.lower() and ("injection" in desc.lower() or "hijack" in desc.lower()):
        detection_text.append("Мониторинг загрузки библиотек в процессы и использование системных вызовов типа CreateRemoteThread, WriteProcessMemory.")
    if "registry" in desc.lower():
        detection_text.append("Включение аудита изменений реестра (Event ID 4657, Sysmon event 13).")
    if "service" in desc.lower():
        detection_text.append("Отслеживание создания, изменения и запуска служб (Event ID 7045, 4697).")
    if "scheduled task" in desc.lower():
        detection_text.append("Мониторинг создания запланированных задач (Event ID 4698, 4702).")
    if "ssh" in desc.lower():
        detection_text.append("Анализ логов SSH-сервера на предмет необычных попыток входа или перехвата сессий.")
    if "dns" in desc.lower():
        detection_text.append("Анализ DNS-запросов на предмет туннелирования или DGA.")
    
    # Убираем дублирование, приводим к списку уникальных строк
    detection_text = list(dict.fromkeys(detection_text))
    return "\n".join(detection_text)

# ----------------------------------------------------------------------
# 3. Функция генерации mitigations (если поле пустое)
# ----------------------------------------------------------------------
def generate_mitigations(entry):
    # Если mitigations уже есть, возвращаем как есть
    if entry.get("mitigations"):
        return entry["mitigations"]
    desc = entry.get("description", "")
    tactic = entry.get("tactic", "")
    mitigations = []
    
    # Общие смягчения в зависимости от тактики
    if tactic in ("Скрытность", "Defense Evasion", "Ухудшение защиты"):
        mitigations.append("Включите защиту на уровне ОС: ASLR, DEP, защита от инъекций процессов.")
        mitigations.append("Используйте EDR и ведение журналов аудита для обнаружения аномалий.")
        mitigations.append("Применяйте политику ограничения выполнения кода (AppLocker, WDAC).")
    if tactic in ("Исполнение", "Execution"):
        mitigations.append("Ограничьте выполнение скриптов и двоичных файлов через политики ограничения выполнения (PowerShell, cmd).")
        mitigations.append("Используйте белые списки приложений для предотвращения запуска недоверенного кода.")
    if tactic in ("Доступ к учетным данным", "Credential Access"):
        mitigations.append("Внедрите многофакторную аутентификацию (MFA) для всех критических систем.")
        mitigations.append("Ограничьте права локальных администраторов, включите защиту LSASS (Credential Guard).")
    if tactic in ("Боковое движение", "Lateral Movement"):
        mitigations.append("Используйте межсетевые экраны для ограничения исходящих подключений по RDP, SMB и другим протоколам.")
        mitigations.append("Ограничьте использование учётных данных с повышенными привилегиями и применяйте принцип наименьших привилегий.")
    if tactic in ("Разведка", "Discovery"):
        mitigations.append("Ограничьте доступ к системным командам (whoami, net, tasklist) для неадминистративных пользователей.")
        mitigations.append("Используйте инструменты контроля доступа к файлам и реестру.")
    if tactic in ("Разработка ресурсов", "Resource Development"):
        mitigations.append("Мониторинг сетевого трафика на наличие скачиваний из неизвестных источников.")
        mitigations.append("Применяйте политики безопасности для управления обновлениями и установкой ПО.")
    if tactic in ("Командование и контроль", "Command and Control"):
        mitigations.append("Фильтруйте и контролируйте исходящий сетевой трафик (прокси, NGFW, DNS-фильтрация).")
        mitigations.append("Используйте решения для обнаружения туннелирования протоколов и DGA.")
    if tactic in ("Коллекция", "Collection"):
        mitigations.append("Применяйте системы предотвращения утечек данных (DLP) для контроля передачи конфиденциальных файлов.")
        mitigations.append("Ограничьте права на доступ к файлам и папкам в соответствии с принципом минимальных привилегий.")
    if tactic in ("Эксфильтрация", "Exfiltration"):
        mitigations.append("Внедрите DLP для обнаружения и блокировки передачи больших объёмов данных за пределы сети.")
        mitigations.append("Используйте шифрование данных в покое и при передаче.")
    if tactic in ("Упорство", "Persistence"):
        mitigations.append("Периодически проводите аудит автозагрузок, служб, запланированных задач и других точек сохранения.")
        mitigations.append("Применяйте политики контроля приложений для предотвращения несанкционированных изменений.")
    if tactic in ("Влияние", "Impact"):
        mitigations.append("Регулярно создавайте резервные копии данных и храните их в изолированном от сети месте.")
        mitigations.append("Внедрите системы восстановления после инцидентов и мониторинг целостности файлов.")
    
    # Добавляем специфические смягчения по описанию
    if "powershell" in desc.lower():
        mitigations.append("Включите режим ограниченного языка PowerShell и используйте журналирование блоков сценариев.")
    if "wmi" in desc.lower():
        mitigations.append("Ограничьте доступ к WMI через настройки DCOM и брандмауэра, разрешайте только авторизованным пользователям.")
    if "dll" in desc.lower() and ("injection" in desc.lower() or "hijack" in desc.lower()):
        mitigations.append("Включите контроль загрузки DLL через AppLocker и используйте защиту от перехвата порядка поиска DLL.")
    if "scheduled task" in desc.lower():
        mitigations.append("Ограничьте создание задач через групповые политики и отслеживайте их изменения.")
    if "registry" in desc.lower():
        mitigations.append("Ограничьте права на запись в ключи реестра, особенно в разделах автозагрузки и сервисов.")
    if "services" in desc.lower():
        mitigations.append("Ограничьте права на изменение и создание служб только привилегированным учётным записям.")
    if "ssh" in desc.lower():
        mitigations.append("Используйте ключи SSH вместо паролей, отключите root-логин и применяйте двухфакторную аутентификацию.")
    if "rdp" in desc.lower():
        mitigations.append("Ограничьте RDP-доступ через шлюзы RDP, используйте NLA и отключайте RDP для обычных пользователей.")
    
    # Если смягчения не добавились, ставим общий текст
    if not mitigations:
        mitigations.append("Следуйте лучшим практикам безопасности: обновляйте ПО, применяйте принцип наименьших привилегий, используйте EDR и ведение журналов.")
    
    mitigations = list(dict.fromkeys(mitigations))
    return mitigations

# ----------------------------------------------------------------------
# 4. Основной цикл обработки
# ----------------------------------------------------------------------
for item in data:
    tid = item["id"]
    
    # ---- Заполнение related_cwe и related_capec ----
    if not item.get("related_cwe") or not item.get("related_capec"):
        if tid in mapping:
            cwe_list, capec_list = mapping[tid]
            if not item.get("related_cwe"):
                item["related_cwe"] = cwe_list
            if not item.get("related_capec"):
                item["related_capec"] = capec_list
        else:
            # Если нет в ручном маппинге, пытаемся угадать по тактике и описанию
            tactic = item.get("tactic", "")
            desc = item.get("description", "")
            if not item.get("related_cwe"):
                if "инъекц" in desc.lower() or "injection" in desc.lower():
                    item["related_cwe"] = ["CWE-94", "CWE-74"]
                elif "обход" in desc.lower() or "bypass" in desc.lower():
                    item["related_cwe"] = ["CWE-284", "CWE-287"]
                elif "сбор" in desc.lower() or "collection" in desc.lower():
                    item["related_cwe"] = ["CWE-200"]
                elif "повышение привилегий" in tactic.lower() or "privilege escalation" in tactic.lower():
                    item["related_cwe"] = ["CWE-269", "CWE-285"]
                elif "устойчивость" in tactic.lower() or "persistence" in tactic.lower():
                    item["related_cwe"] = ["CWE-276", "CWE-732"]
                elif "исполнение" in tactic.lower() or "execution" in tactic.lower():
                    item["related_cwe"] = ["CWE-426"]
                else:
                    item["related_cwe"] = ["CWE-284"]
            if not item.get("related_capec"):
                if "инъекц" in desc.lower():
                    item["related_capec"] = ["CAPEC-242"]
                elif "обход" in desc.lower():
                    item["related_capec"] = ["CAPEC-115", "CAPEC-126"]
                elif "сбор" in desc.lower():
                    item["related_capec"] = ["CAPEC-116"]
                else:
                    item["related_capec"] = ["CAPEC-21", "CAPEC-176"]
    
    # ---- Заполнение detection ----
    if not item.get("detection"):
        item["detection"] = generate_detection(item)
    
    # ---- Заполнение mitigations (если пусто) ----
    if not item.get("mitigations"):
        item["mitigations"] = generate_mitigations(item)

# Сохраняем результат
with open('C:\projects\MITRE_PARSER\output\mitre_attack_filled.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print("Обработка завершена. Результат сохранён в mitre_attack_filled.json")