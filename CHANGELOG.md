```                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
```
***This file contains the history of the changes made to secutils since it was born.***
---
Secutils v3.0  
Release date: 26/Apr/2019 

Features | Changes:  
[+] Translation function redefined (DB File no needed anymore locally, the script will download the current version)
[+] CVSSv3 vector and base score included on Nessus reports (if apply)
[+] The script now performs update check
[-/+] Classes redefined by funtionality (more scalable) 
[-/+] CLI colors redefinition (now works in Windows also)
[-/+] Excel sheets renamed
[-/+] Update from xls to xlsx reports format
[-] Removed funtionality to add reports to previous created Excel files in order to improve speed execution; moreover it's easier to move one sheet from a workbook to another using Excel itself rather than loading a whole file and editing it with python. Thus xlsxwriter is used instead of openpyxl and xlwt/rd.
[-] Acunetix & Netsparker modules temporarily deprecated (working on this and other tools to parse)

---
Secutils v2.5.1  
Release date: 04/Oct/2017  

Features | Changes:  
[+] Nmap scripts added to report
[+] Minor bugs fixed within Acunetix functionality

---
Secutils v2.0  
Release date: 05/May/2016  

Features | Changes:  
[+] Code redesign
[+] More validations in place
[+] Creation of reports from multiple input paths
[+] It is possible to set a custom name/path to a given output file
[+] It is possible to add more reports to a previous created Excel report

Sorry for the n^4 complexity at some methods

---
Secutils v1.2  
Release date: 25/Oct/2015  

Features | Changes:  
[+] Minor bugs fixed

---
Secutils v1.1  
Release date: 02/Aug/2015  

Features | Changes:  
[+] Improved reports creation.
[+] Use of colors in messages for *nix consoles.

---
Secutils v1.0  
Release date: 18/Jul/2015  

Features | Changes:  
[+] Flag names changed.
[+] Algorithm to generate nmap reports improved. Complexity from nlogn to n^2 but more scalable function.
[+] Translation from nessus report with a spacified Excel database. 
[+] Creation of nessus report in two sheets (with both translated and non-translated versions).
[+] Creation of Excel reports from acunetix files in xml format.
[+] Creation of Excel reports from netsparker files in xml format. These files must be generated with the "Detailed Scan Report (XML).xml.cshtml" template stored in the "netsparker template" folder in order to get the complete description from findings.

Supported tools:  
[+] Nmap utilities
[+] Nessus utilities
[+] Acunetix utilities
[+] Netsparker utilities

---
Secutils v0.9 Beta  
Release date: 27/Jun/2015  

Features:  
[+] Creation of Excel reports from nmap enumeration or discovery files in xml format generated with the nmap flag -oX.
[+] Creation of lists of targets (targets.txt) from .xml files obtained from nmap discovery. 
[+] Creation of comma separated lists of open ports (ports.txt) from .xml files obtained from nmap enumeration.
[+] Creation of Excel reports (ReporteVulnerabilidades.xls) from Nessus files in .nessus format generated with the Nessus tool. Also, translation of vulnerabilitis by using a vulnerabilitiesdb.xls file provided in the current working directory.

Supported modules:  
[+] Nmap utilities
[+] Nessus utilities
