```                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
```
## Description
secutils is a small python package that aims to help with report generation from security tools. In the past, it supported Nmap, Nessus, Netsparker, and Acunetix XML outputs; the latest two are deprecated now. If needed, the current structure allows modules scalability, though.

The aim of this tool is to help security teams to save time when creating reports from their findings with automated tools. secutils will generate Excel XLSX reports from data encoding output files from security tools, such as XML. 

## Overview
secutils has a number of command line arguments described below:

```bash
$ secutils --help

usage: secutils.py [-h] [-v] [--no-check] {nmap,nessus} ...

Miscellaneous:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  --no-check     Avoid checking for updates

Available Modules:
  {nmap,nessus}  [FLAGS]

Examples:
    secutils nmap --targets Project/Discovery/ --ports Project/Enum/
    secutils namp --report Project/Discovery/target1 -o AwesomeReportName
    secutils nessus -r Project/target1/nessus Project/target2/nessus/ -T spanish -o AwesomeReportName.xlsx
```

```bash
$ secutils nmap --help

usage: secutils.py nmap [-h] [-t DIR [DIR ...]] [-p DIR [DIR ...]] [-r DIR [DIR ...]] [-o OUTPUT-FILE]

optional arguments:
  -h, --help            show this help message and exit

Nmap Utils:
  -t DIR [DIR ...], --targets DIR [DIR ...]
                        Create a list of IP addresses from nmap xml output files from DIR
  -p DIR [DIR ...], --ports DIR [DIR ...]
                        Create a list of open ports from nmap xml output files from DIR
  -r DIR [DIR ...], --report DIR [DIR ...]
                        Create an XLSX report from nmap xml output files from DIR
  -o OUTPUT-FILE, --output OUTPUT-FILE
                        Set an XLSX output file
```

```bash
$ secutils nessus --help

usage: secutils.py nessus [-h] [-r DIR [DIR ...]] [-s DIR [DIR ...]] [-T LANGUAGE] [-o OUTPUT-FILE]

optional arguments:
  -h, --help            show this help message and exit

Nessus Utils:
  -r DIR [DIR ...], --report DIR [DIR ...]
                        Create an XLSX report from .nessus files from DIR
  -s DIR [DIR ...], --simple-report DIR [DIR ...]
                        Create a TXT simple report from .nessus files from DIR
  -T LANGUAGE, --translate LANGUAGE
                        Use an SQLite database to translate nessus reports. Requires --report
  -o OUTPUT-FILE, --output OUTPUT-FILE
                        Set an XLSX output file
```

## Install 

```bash
$ git clone https://github.com/zkvL7/secutils.git
$ cd secutils
$ python3 -m pip install .

$ secutils --help
```

## Requirements
* ~~[Python 2.7.x](https://www.python.org/downloads/release/python-2718/)~~
* [Python 3](https://www.python.org/downloads/)

> Programmed and tested on Python 2.7.15
> Migrated to Python 3 with `2to3` & tested on Python 3.7.7

### External python packages:

Refer to [requirements](./requirements.txt) file to get details on external python packages used, and install 'em with:

`python3 -m pip install -r requirements.txt --user`

### Vulnerabilities database
secutils allows to automatically translate Nessus vulnerabilities if a database is provided. If Nessus report translation is required from English to any other language, the tool will require a database of translated vulnerabilities. secutils uses an SQLite database file following the structure below:

- Column A: Nessus Plugin ID
- Column B: Name
- Column C: Description
- Column D: Solution

Currently, only Spanish translation is added to the databases set; if you have an update for the vulns described within the `spanish.db` file please send me a mail/dm and I'll be glad to update the file. Also if you can provide a different language schema it would be awesome to add it to the DBs set.

