# Changelog

```                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
```
This file contains the history of the changes made to secutils since it was born.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---
## [3.0.2] - 2020-05-09
### Changed
- Modified update validation method
- Changed this CHANGELOG file to adopt [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format
- Use of `requests` instead of `urllib` and `tqdm` instead of `progress.bar`

### Fixed
- Fixed execution error when setting a report name `NameError: name 'args' is not defined`
- Fixed execution error when downloading lastest version of translation database

---
## [3.0.1] - 2020-05-09
### Changed
- Script migrated to Python3 

---
## [3.0.0] - 2019-04-26
### Added
- The script now performs update check  
- Nessus module
	- CVSSv3 vector and base score included on Nessus reports (if apply)

### Changed
- Classes redefined by funtionality (more scalable)
- CLI colors redefinition (now works in Windows also)
- Excel sheets renamed
Update from xls to xlsx reports format
- Nessus module
	- Translation function redefined (DB File no needed anymore locally, the script will download the current version)  

### Removed
- Remove funtionality to add reports to previous created Excel files in order to improve speed execution; moreover it's easier to move one sheet from a workbook to another using Excel itself rather than loading a whole file and editing it with python. Thus `xlsxwriter`` is used instead of openpyxl and xlwt/rd`.
- Remove Acunetix module
- Remove Netsparker module

---
## [2.5.1] - 2017-10-04
### Added
- Nmap scripts added to report  

### Fixed
- Minor bugs fixed within Acunetix functionality  

### Deprecated
- Acunetix module
- Netsparker module

---
## [2.0.0] - 2016-05-05
### Added
- More validations in place  
- Creation of reports from multiple input paths  
- It is possible to set a custom name/path to a given output file  
- It is possible to add more reports to a previous created Excel report 

### Changed
- Code redesign  
 
> NOTE: Sorry for the n^4 complexity at some methods

---
## [1.0.2] - 2015-10-25
### Fixed
- Minor bugs fixed

---
## [1.0.1] - 2015-08-02
### Changed
- Improved reports creation  
- Use of colors in messages for \*nix consoles  

---
## [1.0.0] - 2015-07-18
### Added
- Acunetix module
	- Creation of Excel reports from acunetix files in xml format  
- Netsparker module
	- Creation of Excel reports from netsparker files in xml format. These files must be generated with the "Detailed Scan Report (XML).xml.cshtml" template stored in the "netsparker template" folder in order to get the complete description from findings 

### Changed
- Nmap module
	- Flag names changed 
	- Algorithm to generate nmap reports improved. Complexity from nlogn to n^2 but more scalable function  
- Nessus module
	- Translation from nessus report with a spacified Excel database  
	- Creation of nessus report in two sheets (with both translated and non-translated versions) 
 
---
## [0.0.9] - 2015-06-27
### Added
- Nmap module
	- Creation of Excel reports from nmap enumeration or discovery files in xml format generated with the nmap flag -oX
	- Creation of lists of targets (targets.txt) from .xml files obtained from nmap discovery  
	- Creation of comma separated lists of open ports (ports.txt) from .xml files obtained from nmap enumeration  
- Nessus module
	- Creation of Excel reports (ReporteVulnerabilidades.xls) from Nessus files in .nessus format generated with the Nessus tool. Also, translation of vulnerabilitis by using a vulnerabilitiesdb.xls file provided in the current working directory  
