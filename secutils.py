#!/usr/bin/env python

# Secutils
# Copyright 2015 Yael Basurto
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os, sys, re
import sqlite3
import urllib2
import xlsxwriter
from glob import glob
from time import sleep
from platform import system
from progress.bar import Bar
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError
from colorama import init, Fore, Back, Style
from argparse import ArgumentParser, RawTextHelpFormatter

# -[ This class contains all functionality associated with nmap utilities -]
class Nmap:
    # XLSX Excel Report configuration variables
    # report output file name/path
    reportName = os.path.abspath('SecutilsReport.xlsx')
    
    # workbook styles 
    stTitle = stText = stVuln = stVulnNF = stCritical = stHigh = stMedium = stLow = None

    separator = '/'

    def __init__(self):
        if system() == 'Windows':
            self.separator = '\\'

    def confWb(self, workbook):    
        # setting workbook styles 
        self.stTitle = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': 'black'})
        self.stText = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stVuln = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'bold': True, 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stVulnNF = workbook.add_format({'font_name': 'Calibri', 'font_color': 'red', 'bold': True, 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stCritical = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#5D0E63'})
        self.stHigh = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#F50606'})
        self.stMedium = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#F5F506'})
        self.stLow = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#01BBB5'})
        
        return workbook

    def setTitle(self, ws):
        # report titles & column withs
        tNmap = [
            'IP', 
            'Hostname', 
            'Port', 
            'Protocol', 
            'Service', 
            'Device', 
            'Detail', 
            'O.S.', 
            'Host scripts']
        wNmap = [15, 20, 7, 10, 15, 35, 65, 35, 65]

        for i in range(len(tNmap)):
            ws.set_column(i, i, wNmap[i])
            ws.write(0, i, tNmap[i], self.stTitle)

    def setPath(self, path):
        for i in range(len(path)):
            if  path[i][-1] != self.separator:
                path[i] = path[i] + self.separator
        return path

    def setOutput(self, output):
        if output[0][-5:] == '.xlsx':
            self.reportName = os.path.abspath(args.output[0])
        else:
            self.reportName = os.path.abspath(args.output[0] + '.xlsx')

    def write_t(self, targets):
        with open("targets.txt","w+") as file:
            for t in targets:
                file.write(t + "\n")

    def getTargets(self, path):
        targets = list()
        # Recursively proceesses all nmap XML files from all specified folders 
        if len(path) > 0:
            # Obtains all nmap XML files from each folder
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                print Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5]
            else:    
                for f in glob(p):
                    print Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ..." 
                    dom = parse(f)
                    nmaprun = dom.documentElement
                    # For each host in nmap XML file
                    for node in nmaprun.getElementsByTagName('host'):
                        # Extracts IP addresses from all hosts with status = "up"
                        if node.getElementsByTagName('status')[0].getAttribute('state') == "up":
                            targets.append(node.getElementsByTagName('address')[0].getAttribute('addr'))
                    dom.unlink()
            del path[0]
            targets.extend(self.getTargets(path))
        return targets

    def write_p(self, ports):
        with open("ports.txt","w+") as file:
            for i in range(len(ports)-1):
                file.write(ports[i]+",")
            file.write(ports[-1])
    
    def getPorts(self, path):
        ports = list()
        # Recursively proceesses all nmap XML files from all specified folders 
        if len(path) > 0:
            # Obtains all nmap XML files from each folder
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                print Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5]
            else:
                for f in glob(p):
                    Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ..."
                    dom = parse(f)
                    nmaprun = dom.documentElement
                    # For each host in nmap XML file
                    for node in nmaprun.getElementsByTagName('host'):
                        # Validate sif host is up & has ports node
                        if node.getElementsByTagName('status')[0].getAttribute('state') == "up" and node.getElementsByTagName('ports'):
                            # For each port in port node extracts port id if state is "open"
                            for port in node.getElementsByTagName('ports')[0].getElementsByTagName('port'):
                                if port.getElementsByTagName('state')[0].getAttribute('state') == "open":
                                    ports.append(port.getAttribute('portid'))
                    dom.unlink()
            del path[0]
            ports.extend(self.getPorts(path))
        return sorted(set(ports))

    def nmap2xls(self, path, ws, row):
        # Recursively proceesses all nmap XML files from all specified folders 
        if len(path) > 0:
            # Obtains all nmap XML files from each folder
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5]
            else:
                for f in glob(p):
                    print Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ..." 
                    try:
                        dom = parse(f)
                        nmaprun = dom.documentElement
                        # For each host in nmap XML file retrieves all asociated information if host is up
                        for node in nmaprun.getElementsByTagName('host'):
                            # If host is up, extracts IP address
                            if node.getElementsByTagName('status')[0].getAttribute('state') == "up":
                                ip = node.getElementsByTagName('address')[0].getAttribute('addr')
                                # Saves a pointer to the first row of the current host
                                hostrow = row
                                # Extracts hostname if exists
                                hostname = os = ""
                                if node.getElementsByTagName('hostnames') and node.getElementsByTagName('hostnames')[0].getElementsByTagName('hostname'):
                                    hostname = node.getElementsByTagName('hostnames')[0].getElementsByTagName('hostname')[0].getAttribute('name')
                                # Extracts OS parameter if exists         
                                if node.getElementsByTagName('os') and node.getElementsByTagName('os')[0].getElementsByTagName('osmatch'):
                                    for o in node.getElementsByTagName('os')[0].getElementsByTagName('osmatch'):
                                        os = os + o.getAttribute('name') + " "  + o.getAttribute('accuracy') + "%\n"
                                # Extracts all open ports if any 
                                if node.getElementsByTagName('ports'):
                                    for pto in node.getElementsByTagName('ports')[0].getElementsByTagName('port'):
                                        # If port is open, extracts port id & protocol
                                       if pto.getElementsByTagName('state')[0].getAttribute('state') == "open":
                                            port = pto.getAttribute('portid')
                                            protocol = pto.getAttribute('protocol')
                                            # Extracts service & all asociated information if any 
                                            if pto.getElementsByTagName('service'):
                                                service = pto.getElementsByTagName('service')[0].getAttribute('name')
                                                product = pto.getElementsByTagName('service')[0].getAttribute('product')
                                                version = pto.getElementsByTagName('service')[0].getAttribute('version')
                                                extrainfo = pto.getElementsByTagName('service')[0].getAttribute('extrainfo')
                                            # Extract script information if any
                                            detail = ""
                                            if pto.getElementsByTagName('script'):
                                                sindex = 0
                                                for s in pto.getElementsByTagName('script'):
                                                    detail = detail + pto.getElementsByTagName('script')[sindex].getAttribute('id') + " : " + pto.getElementsByTagName('script')[sindex].getAttribute('output') + "\n\n"
                                                    sindex += 1
                                            # Write all extracted information to Excel report                     
                                            ws.write(row, 0, ip, self.stText)
                                            ws.write(row, 1, hostname, self.stText)
                                            ws.write(row, 2, port, self.stText)
                                            ws.write(row, 3, protocol, self.stText)
                                            ws.write(row, 4, service, self.stText)
                                            ws.write(row, 5, product+" "+version+" "+extrainfo, self.stText)
                                            ws.write(row, 6, detail, self.stText)
                                            ws.write(row, 7, os, self.stText)
                                            row += 1
                                # Check if scanning has run with scripts
                                if node.getElementsByTagName('hostscript'):
                                    hscript = ""
                                    for script in node.getElementsByTagName('hostscript')[0].getElementsByTagName('script'):
                                        hscript = hscript + script.getAttribute('id') + "\n" + script.getAttribute('output') + "\n\n"
                                    ws.merge_range(hostrow, 8, row-1, 8, hscript, self.stText)
                        dom.unlink()
                    except ExpatError:
                        print Fore.RED + "[!] [ERROR] Apparently there's a bad XML file"; raise
                    except IndexError:
                        print Fore.RED + "[!] [ERROR] A value in the XML file is missing!"; raise
                    except:
                        print Fore.RED + "[!] [Unexpected Error]"; raise
            del path[0]
            self.nmap2xls(path, ws, row)
        else:
            ws.autofilter(0, 0, row-1, 7)

# -[ This class contains all functionality associated with nessus utilities -]
class Nessus:
    # XLSX Excel Report configuration variables
    # report output file name/path
    reportName = os.path.abspath('SecutilsReport.xlsx')
    
    # workbook styles 
    stTitle = stText = stVuln = stVulnNF = stCritical = stHigh = stMedium = stLow = None

    separator = '/'

    def __init__(self):
        init(autoreset=True)
        if system() == 'Windows':
            self.separator = '\\'

    def confWb(self, workbook):    
        # setting workbook styles 
        self.stTitle = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': 'black'})
        self.stText = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stVuln = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'bold': True, 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stVulnNF = workbook.add_format({'font_name': 'Arial', 'font_color': 'red', 'bold': True, 'align': 'left', 'valign': 'vcenter', 'text_wrap': True})
        self.stCritical = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#4A00BB'})
        self.stHigh = workbook.add_format({'font_name': 'Calibri', 'font_color': 'white', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#F50606'})
        self.stMedium = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#F5F506'})
        self.stLow = workbook.add_format({'font_name': 'Calibri', 'font_color': 'black', 'align': 'center', 'valign': 'vcenter', 'bg_color': '#01BBB5'})
        
        return workbook

    def setTitle(self, ws):
        # report titles & column withs
        tNessus = [
            'Nessus ID', 
            'Vulnerability', 
            'Risk', 
            'IP', 
            'Port', 
            'Service', 
            'Protocol', 
            'Description', 
            'Solution', 
            'CVE', 
            'CVSS', 
            'Plugin output', 
            'References']
        wNessus = [15, 30, 10, 15, 10, 10, 10, 80, 80, 15, 15, 80, 40]

        for i in range(len(tNessus)):
            ws.set_column(i, i, wNessus[i])
            ws.write(0, i, tNessus[i], self.stTitle)

    def setPath(self, path):
        for i in range(len(path)):
            if  path[i][-1] != self.separator:
                path[i] = path[i] + self.separator
        return path

    def setOutput(self, output):
        if output[0][-5:] == '.xlsx':
            self.reportName = os.path.abspath(args.output[0])
        else:
            self.reportName = os.path.abspath(args.output[0] + '.xlsx')

    def download_db(self, lang):
        print Fore.CYAN + "Downloading lastest version of %s database ..." % (lang)
        url = "https://github.com/zkvL7/secutils/raw/master/VulnsDBs/"+lang+".db"
        
        data = urllib2.urlopen(url)
        data_lenght = int(data.info()['Content-Length'])
        block_size = 256
        with open(lang+'.db','wb') as db:
            with Bar('Processing', max=data_lenght/block_size, suffix='%(index)d/%(max)d - %(percent).1f%% - %(eta)ds') as bar:
                while True:
                    chuck = data.read(block_size)
                    if not chuck:
                        break
                    else:
                        db.write(chuck)
                        bar.next()

    def getVulnT(self, c, id):
        vuln = c.execute('SELECT * FROM vulns WHERE "NessusID"=(?)', (id,)).fetchone()
        return vuln

    def nessus2xls(self, path, ws, row, *args):
        # Recursively proceesses all nessus files from all specified folders
        if len(path) > 0:
            # Obtains all nessus files from each folder
            p = path[0] + '*.nessus'
            if (len(glob(p)) == 0):
                print Fore.RED + "[!] [ERROR] There's no nessus files in " + p[:-8]
            else:
                for f in glob(p):
                    print Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ..." 
                    try:
                        dom = parse(f)
                        nessusclientdata = dom.documentElement
                        # For each host in nessus file registered with the ReportHost node
                        for node in nessusclientdata.getElementsByTagName('ReportHost'):
                            ip = node.getAttribute('name')
                            # For each vulnerability in nessus file registered with the ReportItem node 
                            for item in node.getElementsByTagName('ReportItem'):
                                risk = item.getAttribute('severity')
                                # If risk is different from informative, appends a row in Excel report
                                if risk != "0":
                                    # Extracts all related vulnerability information
                                    pluginID = item.getAttribute('pluginID')
                                    vulnerability = item.getAttribute('pluginName')
                                    port = item.getAttribute('port')
                                    service = item.getAttribute('svc_name')
                                    protocol = item.getAttribute('protocol')
                                    description = item.getElementsByTagName('description')[0].childNodes[0].data
                                    solution = item.getElementsByTagName('solution')[0].childNodes[0].data
                                    cve = cvss = output = ref = ""
                                    # Extracts CVE information if exists
                                    if item.getElementsByTagName('cve'):
                                        for c in item.getElementsByTagName('cve'):
                                            cve = cve + c.childNodes[0].data + "\n"
                                    # Extracts CVSS information if exists
                                    if item.getElementsByTagName('cvss3_base_score'):
                                        cvss = "CVSS3 Base Score: " + item.getElementsByTagName('cvss3_base_score')[0].childNodes[0].data + "\n"
                                    if item.getElementsByTagName('cvss3_vector'):
                                        cvss = cvss + "CVSS3 Vector: " + item.getElementsByTagName('cvss3_vector')[0].childNodes[0].data + "\n"
                                    if item.getElementsByTagName('cvss_base_score'):
                                        cvss = cvss + "CVSS Base Score: " + item.getElementsByTagName('cvss_base_score')[0].childNodes[0].data + "\n"
                                    if item.getElementsByTagName('cvss_temporal_score'): 
                                        cvss = cvss + "CVSS Temporal Score:" + item.getElementsByTagName('cvss_temporal_score')[0].childNodes[0].data + "\n"
                                    if item.getElementsByTagName('cvss_temporal_vector'):
                                        cvss = cvss + "CVSS Temporal Vector:" + item.getElementsByTagName('cvss_temporal_vector')[0].childNodes[0].data + "\n"
                                    if item.getElementsByTagName('cvss_vector'):
                                        cvss = cvss + "CVSS Vector: " + item.getElementsByTagName('cvss_vector')[0].childNodes[0].data + "\n"
                                    # Extracts plugin output if exists
                                    if item.getElementsByTagName('plugin_output'):
                                        output = item.getElementsByTagName('plugin_output')[0].childNodes[0].data
                                    # Extracts references if any
                                    if item.getElementsByTagName('see_also'):
                                        ref = item.getElementsByTagName('see_also')[0].childNodes[0].data
                                    
                                    # Translates vulnerabilities if specified by -T optional parameter
                                    found = False
                                    if args:
                                        lang_vuln = self.getVulnT(args[0], int(pluginID))
                                        if lang_vuln:
                                            found = True
                                            vulnerability = lang_vuln[1]
                                            description = lang_vuln[2]
                                            solution = lang_vuln[3]

                                    # Write all extracted information to Excel report
                                    ws.write(row, 0, pluginID, self.stText)
                                    if found or not args:
                                        ws.write(row, 1, vulnerability, self.stVuln)
                                    else:
                                        ws.write(row, 1, vulnerability, self.stVulnNF)
                                    if risk == "1":
                                        ws.write(row, 2, "Low", self.stLow)
                                    if risk == "2":
                                        ws.write(row, 2, "Medium", self.stMedium)
                                    if risk == "3":
                                        ws.write(row, 2, "High", self.stHigh)
                                    if risk == "4":
                                        ws.write(row, 2, "Critical", self.stCritical)
                                    ws.write(row, 3, ip, self.stText)
                                    ws.write(row, 4, port, self.stText)
                                    ws.write(row, 5, service, self.stText)
                                    ws.write(row, 6, protocol, self.stText)
                                    ws.write(row, 7, description, self.stText)
                                    ws.write(row, 8, solution, self.stText)
                                    ws.write(row, 9, cve, self.stText)
                                    ws.write(row, 10, cvss, self.stText)
                                    ws.write(row, 11, output[0:32767], self.stText)
                                    ws.write_string(row, 12, ref, self.stText)
                                    row += 1
                        dom.unlink()
                    except ExpatError:
                        print Fore.RED + "[!] [ERROR] Apparently there's a bad XML file"; raise
                    except IndexError:
                        print Fore.RED + "[!] [ERROR] A value in the XML file is missing!"; raise
                    except:
                        print Fore.RED + "[!] [Unexpected Error]"; raise
            del path[0]
            if args:
                self.nessus2xls(path, ws, row, args[0])
            else:
                self.nessus2xls(path, ws, row)
        else:
            ws.autofilter(0, 0, row-1, 11) 

def checkUpdate():
    try:
        current = '3.0'
        pattern = re.compile(r"Secutils\sv\d+\.\d+\.?\d*")
        url = 'https://raw.githubusercontent.com/zkvL7/secutils/master/CHANGELOG.md'
        data = urllib2.urlopen(url).read(1000)

        if pattern.findall(str(data))[0].split("v")[1] != current:
            print Fore.YELLOW + Back.BLUE + Style.BRIGHT + "[!] There's an update available at https://github.com/zkvL7/secutils [!]" + Style.RESET_ALL + "\n"
    except:
        print Fore.RED + "[!] ERROR: Something happend when checking updates"
        pass

def options():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter,
        epilog='''EXAMPLES: 
        python secutils.py -t Project/Discovery/ -p Project/Enum/
        python secutils.py -rn Project/Discovery/target1 -o Report
        python secutils.py -rN Project/target1/nessus Project/target2/nessus/ -T spanish -o Report.xls''')
    
    parser._optionals.title = "MISC"
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.6.0')
    parser.add_argument('-o', metavar='OUTPUT-FILE', dest='output', action='append', help='Set an xlsx output file')

    nmapGroup = parser.add_argument_group('NMAP REPORT')
    nmapGroup.add_argument('-t', metavar='DIR', nargs='+', dest='targets', action='append', help='Create a list of targets from nmap files in xml format located in DIR')
    nmapGroup.add_argument('-p', metavar='DIR', nargs='+', dest='ports', action='append', help='Create list of open ports from nmap files in xml format located in DIR')
    nmapGroup.add_argument('-rn', metavar='DIR', nargs='+', dest='nmap', action='append', help='Create an XLS report from nmap files in xml format located in DIR')
    
    nessusGroup = parser.add_argument_group('NESSUS REPORT')
    nessusGroup.add_argument('-rN', metavar='DIR', nargs='+', dest='nessus', action='append', help='Create an XLS report from .nessus files located in DIR')
    nessusGroup.add_argument('-T', metavar='LANGUAGE', dest='lang', help='Use an xls database FILE to translate nessus reports. Must be used along with -rN')

    if len(sys.argv) == 1:
        return parser.parse_args('--help'.split())
    else:
        return parser.parse_args()

def main():
    init(autoreset=True)
    print Fore.CYAN + '''
                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \\  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
              - secutils v3.0 -
                c0d3d by zkvL
    '''
    checkUpdate()
    args = options()
    try:
        # Options for Nmap module operations
        if args.targets or args.ports or args.nmap:
            nmap = Nmap()
            if args.targets:
                print Fore.YELLOW + "[-] Retrieve alive IPs from nmap output:"
                nmap.write_t(nmap.getTargets(nmap.setPath(args.targets[0])))
                print Fore.GREEN + "[+] targets.txt file successfully created!"
                
            if args.ports:
                print Fore.YELLOW + "[-] Retrieve open ports from nmap output"
                nmap.write_p(nmap.getPorts(nmap.setPath(args.ports[0])))
                print Fore.GREEN + "[+] ports.txt file successfully created!"
            
            if args.nmap:
                if args.output:
                    nmap.setOutput(args.output)

                # Create the Excel file & set custom format
                print Fore.YELLOW + "[-] Create Excel report from NMAP outputs:"
                with xlsxwriter.Workbook(nmap.reportName,{'strings_to_urls': False}) as workbook:
                    wb = nmap.confWb(workbook)
                    ws = wb.add_worksheet('Nmap Enumeration')
                    nmap.setTitle(ws)
                    nmap.nmap2xls(nmap.setPath(args.nmap[0]), ws, 1)
                    print Fore.GREEN + "[+] Enumeration sheet was successfully created into file:\n" + nmap.reportName + "\n"

        # Options for Nessus module operations
        if args.nessus:
            nessus = Nessus()
            if args.output:
                nessus.setOutput(args.output)
            
            # Create the Excel file & set custom format
            print Fore.YELLOW + "[-] Create Excel report from NESSUS outputs:"
            with xlsxwriter.Workbook(nessus.reportName,{'strings_to_urls': False}) as workbook:
                wb = nessus.confWb(workbook)
                ws = wb.add_worksheet('Vulnerability Assessment')
                nessus.setTitle(ws)
                if args.lang and args.lang == 'spanish':
                    # Downloads the lang.db SQLite file and open the database
                    nessus.download_db(args.lang)
                    db_conn = sqlite3.connect(args.lang+'.db')
                    cursor = db_conn.cursor()
                    nessus.nessus2xls(nessus.setPath(args.nessus[0]), ws, 1, cursor)
                    db_conn.close()
                elif not args.lang or (args.lang and args.lang != 'spanish'):
                    if args.lang and args.lang != 'spanish':
                        print Fore.RED + "[!] Currently only spanish language is supported; file will not be translated" 
                    nessus.nessus2xls(nessus.setPath(args.nessus[0]), ws, 1)
                print Fore.GREEN + "[+] Vuln Assessment sheet was successfully created into file:\n" +nessus.reportName + "\n"
    except IOError:
        print Fore.RED + "[!] ERROR: Fail to open necessary files"
    except:
        print Fore.RED + "[!] [Unexpected Error]"
        raise

if __name__ == '__main__':
    main()