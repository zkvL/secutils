```                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
```
## Description
secutils is a python-written small set of utilities that helps with report generation from security tools such as Nmap, Nessus, Netsparker and Acunetix (Netsparker and Acunetix are currently being updated). 

The aim of this tool is to help security teams to save time when creating reports from their findings with automated tools. secutils will generate Excel XLSX reports to allow having all the information from different tools in one single report.

## Overview
> secutils has a number of command line arguments described below:

```
$ secutils --help
usage: secutils.py [-h] [-v] [-o OUTPUT-FILE] [-t DIR [DIR ...]]
                   [-p DIR [DIR ...]] [-rn DIR [DIR ...]] [-rN DIR [DIR ...]]
                   [-T LANGUAGE]

MISC:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
  -o OUTPUT-FILE     Set an xlsx output file

NMAP REPORT:
  -t DIR [DIR ...]   Create a list of targets from nmap files in xml format located in DIR
  -p DIR [DIR ...]   Create list of open ports from nmap files in xml format located in DIR
  -rn DIR [DIR ...]  Create an XLS report from nmap files in xml format located in DIR

NESSUS REPORT:
  -rN DIR [DIR ...]  Create an XLS report from .nessus files located in DIR
  -T LANGUAGE        Use an xls database FILE to translate nessus reports. Must be used along with -rN

EXAMPLES: 
        python secutils.py -t Project/Discovery/ -p Project/Enum/
        python secutils.py -rn Project/Discovery/target1 -o Report
        python secutils.py -rN Project/target1/nessus Project/target2/nessus/ -T spanish -o Report.xls

```
## Requirements
* [Python 2.7.x](https://www.python.org)

> Programmed and tested on Python 2.7.15

* External python packages:
  - [xlsxwriter](https://xlsxwriter.readthedocs.io/index.html)
  - [colorama](https://pypi.org/project/colorama/)
  - [progress](https://pypi.org/project/progress/)

> Try: pip install -r requirements.txt --user

### Vulnerabilities database
Only if nessus report translation is required. In order to translate the vulnerabilities reported by Nessus, it is necessary a database of translated vulnerabilities. secutils uses a SQLite database file following the structure below:

- Column A: Nessus Plugin ID
- Column B: Name
- Column C: Description
- Column D: Solution

Currently only spanish translation is supported; if you have an update for the vulns described within the spanish.db please send me a mail and I'll be glad to update the file. Also if you can provide a different language schema I'll update the tool to support it.

### Contact
Yael Basurto Esquivel (zkvL)
zkvL7@protonmail.com
