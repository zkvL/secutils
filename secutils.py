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

import os, sys, re, xlwt, xlrd
from glob import glob
from xml.dom.minidom import parse
from platform import system
from xlutils.copy import copy
from xml.parsers.expat import ExpatError
from argparse import ArgumentParser, RawTextHelpFormatter

class Secutils():
    ''' colors '''
    WHITE = '\033[97m'      # info 0
    CYAN = '\033[96m'       # banner 1
    PURPLE = '\033[95m'     # verbose 2
    YELLOW = '\033[93m'     # process 3
    GREEN = '\033[92m'      # success 4
    RED = '\033[91m'        # error 5
    ENDC = '\033[0m'

    ''' report output file '''
    reportName = os.path.abspath('SecutilsReport.xls')
    separator = '/'

    ''' xls styles '''
    sTitle = xlwt.easyxf('font: name Arial, colour white, bold on; pattern: pattern solid, fore_colour gray80; align: horiz center')
    sText = xlwt.easyxf('font: name Arial, colour black; align: wrap 1, vert top')
    sVuln = xlwt.easyxf('font: name Arial, colour black, bold on; align: wrap 1')
    sVulnNF = xlwt.easyxf('font: name Arial, colour red, bold on; align: wrap 1')
    sCritical = xlwt.easyxf('font: colour white; pattern: pattern solid, fore_colour dark_purple;')
    sHigh = xlwt.easyxf('font: colour white; pattern: pattern solid, fore_colour red;')
    sMedium = xlwt.easyxf('pattern: pattern solid, fore_colour yellow;')
    sLow = xlwt.easyxf('pattern: pattern solid, fore_colour aqua;')
    
    ''' report titles '''
    tNmap = ['IP', 'Hostname', 'Port', 'Protocol', 'Service', 'Device', 'Detail', 'O.S.', 'Host scripts']
    tNessus = ['Nessus ID', 'Vulnerability', 'Risk', 'IP', 'Port', 'Service', 'Protocol', 'Description', 'Solution', 'CVE', 'CVSS', 'Plugin output', 'References']
    tWeb = ['Vulnerability', 'Affected Item', 'Parameter', 'Detail', 'Risk', 'Description', 'Impact', 'Solution', 'Request', 'Response', 'CVE', 'CVSS', 'References']
    
    ''' report columns width '''
    wNmap = [15, 20 , 7, 10, 15, 35, 65, 35, 65]
    wNessus = [15, 30 , 10, 15, 10, 10, 10, 80, 80, 15, 15, 80, 40]
    wWeb = [30, 30 , 10, 50, 10, 80, 50, 80, 80, 80, 15, 15, 40]
    
    def __init__(self):
        if system() == 'Windows':
            self.WHITE = ''
            self.CYAN = ''
            self.PURPLE = ''
            self.YELLOW = ''
            self.GREEN = ''
            self.RED = ''
            self.ENDC = ''
            self.separator = '\\'
            
    def printMsg(self, mtype, msg):
        if mtype == 0:
            print self.WHITE + msg + self.ENDC
        elif mtype == 1:
            print self.CYAN + msg + self.ENDC
        elif mtype == 2:
            print self.PURPLE + msg + self.ENDC
        elif mtype == 3:
            print self.YELLOW + msg + self.ENDC
        elif mtype == 4:
            print self.GREEN + msg + self.ENDC
        elif mtype == 5:
            print self.RED + msg + self.ENDC

    def setPath(self, path):
        for i in range(len(path)):
            if  path[i][-1] != self.separator:
                path[i] = path[i] + self.separator
        return path
        
    def setWb(self):
        sheet_names = list()
        if os.path.isfile(self.reportName):
            wb = copy(xlrd.open_workbook(self.reportName, formatting_info=1))
            sheets = wb._Workbook__worksheets
            for s in sheets:
                sheet_names.append(s.get_name()) 
            return wb, sheet_names
        else:
            return xlwt.Workbook(encoding='utf-8'), sheet_names
           
    def setTitle(self, ws, titles, widths):
        for i in range(0, len(titles)):
            ws.col(i).width = 256 * widths[i]
            ws.write(0, i, titles[i], self.sTitle)
    
    '''  nmap module '''
    def getTargets(self, path):
        targets = list()
        # Recursively proceesses all nmap XML files from all specified folders 
        if len(path) > 0:
            # Obtains all nmap XML files from each folder
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                self.printMsg(5, "[!] [Error] There's no xml files in " + p[:-5])
            else:    
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
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
    
    def getPorts(self, path):
        ports = list()
        # Recursively proceesses all nmap XML files from all specified folders 
        if len(path) > 0:
            # Obtains all nmap XML files from each folder
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                self.printMsg(5, "[!] [Error] There's no xml files in " + p[:-5])                    
            else:
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
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
                self.printMsg(5, "[!] [Error] There's no xml files in " + p[:-5])
            else:
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
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
                                            ws.write(row, 0, ip, self.sText)
                                            ws.write(row, 1, hostname, self.sText)
                                            ws.write(row, 2, port, self.sText)
                                            ws.write(row, 3, protocol, self.sText)
                                            ws.write(row, 4, service, self.sText)
                                            ws.write(row, 5, product+" "+version+" "+extrainfo, self.sText)
                                            ws.write(row, 6, detail, self.sText)
                                            ws.write(row, 7, os, self.sText)
                                            row += 1
                                # Check if scanning has run with scripts
                                if node.getElementsByTagName('hostscript'):
                                    hscript = ""
                                    for script in node.getElementsByTagName('hostscript')[0].getElementsByTagName('script'):
                                        hscript = hscript + script.getAttribute('id') + "\n" + script.getAttribute('output') + "\n\n"
                                    ws.write_merge(hostrow, row-1, 8, 8, hscript, self.sText)
                        dom.unlink()
                    except ExpatError:
                        self.printMsg(5, "[!] [Error] Apparently there's a bad XML file"); raise
                    except IndexError:
                        self.printMsg(5, "[!] [Error] A value in the XML file is missing!"); raise
                    except:
                        self.printMsg(5, "[!] [Unexpected Error]"); raise
            del path[0]
            self.nmap2xls(path, ws, row)
       
    '''  nessus module '''
    def nessus2xls(self, path, ws, row, *db):
        # Recursively proceesses all nessus files from all specified folders
        if len(path) > 0:
            # Obtains all nessus files from each folder
            p = path[0] + '*.nessus'
            if (len(glob(p)) == 0):
                self.printMsg(5, "[!] [Error] There's no nessus files in " + p[:-8])
            else:
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
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
                                    if item.getElementsByTagName('cvss_base_score'):
                                        cvss = "CVSS Base Score: " + item.getElementsByTagName('cvss_base_score')[0].childNodes[0].data
                                    if item.getElementsByTagName('cvss_temporal_score'): 
                                        cvss = cvss + "\nCVSS Temporal Score:" + item.getElementsByTagName('cvss_temporal_score')[0].childNodes[0].data
                                    if item.getElementsByTagName('cvss_temporal_vector'):
                                        cvss = cvss + "\nCVSS Temporal Vector:" + item.getElementsByTagName('cvss_temporal_vector')[0].childNodes[0].data
                                    if item.getElementsByTagName('cvss_vector'):
                                        cvss = cvss + "\nCVSS Vector: " + item.getElementsByTagName('cvss_vector')[0].childNodes[0].data
                                    # Extracts plugin output if exists
                                    if item.getElementsByTagName('plugin_output'):
                                        output = item.getElementsByTagName('plugin_output')[0].childNodes[0].data
                                    # Extracts references if any
                                    if item.getElementsByTagName('see_also'):
                                        ref = item.getElementsByTagName('see_also')[0].childNodes[0].data
                                    # Translates vulnerabilities if specified by DB optional parameter
                                    found = False
                                    if db:
                                        vulns = xlrd.open_workbook(db[0])
                                        vsh = vulns.sheet_by_index(0)
                                        # Search for PlugnID in vulnerability Excel DB & if found vulnerability, description and solution parameters are replaced with translated values
                                        for vrow in range(1, vsh.nrows):
                                            try:
                                                if int(pluginID) == int(vsh.cell_value(rowx=vrow,colx=0)):
                                                    vulnerability = vsh.cell_value(rowx=vrow,colx=1)
                                                    description = vsh.cell_value(rowx=vrow,colx=2)
                                                    solution = vsh.cell_value(rowx=vrow,colx=3)
                                                    found = True
                                                    break
                                            except ValueError:
                                                continue
                                    # Write all extracted information to Excel report
                                    ws.write(row, 0, pluginID, self.sText)
                                    if found or not db:
                                        ws.write(row, 1, vulnerability, self.sVuln)
                                    else:
                                        ws.write(row, 1, vulnerability, self.sVulnNF)
                                    if risk == "1":
                                        ws.write(row, 2, "Low", self.sLow)
                                    if risk == "2":
                                        ws.write(row, 2, "Medium", self.sMedium)
                                    if risk == "3":
                                        ws.write(row, 2, "High", self.sHigh)
                                    if risk == "4":
                                        ws.write(row, 2, "Critical", self.sCritical)
                                    ws.write(row, 3, ip, self.sText)
                                    ws.write(row, 4, port, self.sText)
                                    ws.write(row, 5, service, self.sText)
                                    ws.write(row, 6, protocol, self.sText)                            
                                    ws.write(row, 7, description, self.sText)
                                    ws.write(row, 8, solution, self.sText)
                                    ws.write(row, 9, cve, self.sText)
                                    ws.write(row, 10, cvss, self.sText)
                                    ws.write(row, 11, output[0:32767], self.sText)
                                    ws.write(row, 12, ref, self.sText)
                                    row += 1
                        dom.unlink()
                    except ExpatError:
                        self.printMsg(5, "[!] [Error] Apparently there's a bad XML file"); raise
                    except IndexError:
                        self.printMsg(5, "[!] [Error] A value in the XML file is missing!"); raise
                    except:
                        self.printMsg(5, "[!] [Unexpected Error]"); raise
            del path[0]
            if db:
                self.nessus2xls(path, ws, row, db[0])
            else:
                self.nessus2xls(path, ws, row)
    
    '''  acunetix module '''     
    def acunetix2xls(self, path, ws, row):
        if len(path) > 0:
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                self.printMsg(5, "[!] [Error] There's no xml files in " + p[:-5])
            else:
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
                    try:
                        dom = parse(f)
                        scangroup = dom.documentElement
                        # For each vulnerability in XML file registered with the ReportItem node
                        for node in scangroup.getElementsByTagName('ReportItem'):
                            # If risk is different from informative, appends a row in Excel report
                            risk = node.getElementsByTagName('Severity')[0].childNodes[0].data
                            if "low" in risk or "medium" in risk or "high" in risk or "critical" in risk:
                                vulnerability = affected = detail = description = impact = solution = request = response = cve = cvss = ref = "N/A"

                                vulnerability = node.getElementsByTagName('Name')[0].childNodes[0].data
                                # Extracts affected element if exists 
                                if node.getElementsByTagName('Affects')[0].childNodes:
                                    affected = node.getElementsByTagName('Affects')[0].childNodes[0].data 
                                # Extracts vulnerability detail if exists & cleans all htlm tags 
                                if node.getElementsByTagName('Details')[0].childNodes:
                                    detail = node.getElementsByTagName('Details')[0].childNodes[0].data
                                    detail = re.sub("<.*?>", " ", detail)
                                # Extracts vulnerability description if exists 
                                if node.getElementsByTagName('Description')[0].childNodes:
                                    description = re.sub("<.*?>", "", node.getElementsByTagName('Description')[0].childNodes[0].data)
                                # Extracts vulnerability impact if exists 
                                if node.getElementsByTagName('Impact')[0].childNodes:
                                    impact = node.getElementsByTagName('Impact')[0].childNodes[0].data
                                # Extracts vulnerability solution if exists 
                                if node.getElementsByTagName('Recommendation')[0].childNodes:
                                    solution = node.getElementsByTagName('Recommendation')[0].childNodes[0].data
                                # Extracts request & response if exists 
                                if node.getElementsByTagName('TechnicalDetails')[0].getElementsByTagName('Request') and node.getElementsByTagName('TechnicalDetails')[0].getElementsByTagName('Request')[0].childNodes:
                                    request = node.getElementsByTagName('TechnicalDetails')[0].getElementsByTagName('Request')[0].childNodes[0].data
                                    response = node.getElementsByTagName('TechnicalDetails')[0].getElementsByTagName('Response')[0].childNodes[0].data
                                # Extracts CVE information if exists 
                                if node.getElementsByTagName('CVEList')[0].getElementsByTagName('CVE'):
                                    for c in node.getElementsByTagName('CVEList')[0].getElementsByTagName('CVE'):
                                        cve = cve + c.getElementsByTagName('Id')[0].childNodes[0].data + "\n"
                                # Extracts CVSS information if exists 
                                if node.getElementsByTagName('CVSS')[0].getElementsByTagName('Score') and node.getElementsByTagName('CVSS')[0].getElementsByTagName('Score')[0].childNodes:
                                    cvss = "Base Score:" + " " + node.getElementsByTagName('CVSS')[0].getElementsByTagName('Score')[0].childNodes[0].data + " " + node.getElementsByTagName('CVSS')[0].getElementsByTagName('Descriptor')[0].childNodes[0].data
                                # Extracts references if any 
                                if node.getElementsByTagName('References')[0].getElementsByTagName('Reference'):
                                    for r in node.getElementsByTagName('References')[0].getElementsByTagName('Reference'):
                                        ref = ref + r.getElementsByTagName('URL')[0].childNodes[0].data + "\n"
                                # Write all extracted information to Excel report 
                                ws.write(row, 0, vulnerability, self.sVuln)
                                ws.write(row, 1, affected, self.sText)
                                ws.write(row, 3, detail, self.sText)
                                if "low" in risk:
                                    ws.write(row, 4, "Low", self.sLow) 
                                elif "medium" in risk:
                                    ws.write(row, 4, "Medium", self.sMedium) 
                                elif "high" in risk:
                                    ws.write(row, 4, "High", self.sHigh) 
                                if "critical" in risk:
                                    ws.write(row, 4, "Critical", self.sCritical) 
                                ws.write(row, 5, description, self.sText)
                                ws.write(row, 6, impact, self.sText)
                                ws.write(row, 7, solution, self.sText)
                                ws.write(row, 8, request, self.sText)
                                ws.write(row, 9, response, self.sText)
                                ws.write(row, 10, cve, self.sText)
                                ws.write(row, 11, cvss, self.sText)
                                ws.write(row, 12, ref, self.sText)
                                row += 1
                        dom.unlink()
                    except ExpatError:
                        self.printMsg(5, "[!] [Error] Apparently there's a bad XML file"); raise
                    except IndexError:
                        self.printMsg(5, "[!] [Error] A value in the XML file is missing!"); raise
                    except:
                        self.printMsg(5, "[!] [Unexpected Error]"); raise
            del path[0]
            self.acunetix2xls(path, ws, row)

    '''  netsparker module '''         
    def netsparker2xls(self, path, ws, row):
        if len(path) > 0:
            p = path[0] + '*.xml'
            if (len(glob(p)) == 0):
                self.printMsg(5, "[!] [Error] There's no xml files in " + p[:-5])
            else:
                for f in glob(p):
                    self.printMsg(3, "Processing " + f.split(self.separator)[-1] + " ...")
                    try:
                        dom = parse(f)
                        netsparker = dom.documentElement
                        # For each vulnerability in XML file registered with the vulnerability node
                        for node in netsparker.getElementsByTagName('vulnerability'):
                            # If risk is different from informative, appends a row in Excel report
                            risk = node.getElementsByTagName('severity')[0].childNodes[0].data
                            if "Low" in risk or "Medium" in risk or "Important" in risk or "Critical" in risk:
                                affected = parameter = detail = description = request = response = ref = "N/A"
                                
                                # Extracts vulnerability & affected element if exists
                                vulnerability =  node.getAttribute('name')
                                if node.getElementsByTagName('url')[0].childNodes:
                                    affected = node.getElementsByTagName('url')[0].childNodes[0].data
                                # Extracts affected parameter if exists
                                if node.getElementsByTagName('vulnerableparameter'):
                                    parameter = node.getElementsByTagName('vulnerableparameter')[0].childNodes[0].data
                                # Extracts vulnerability detail if exists
                                if node.getElementsByTagName('extrainformation')[0].getElementsByTagName('info')[0].childNodes:
                                    detail = node.getElementsByTagName('extrainformation')[0].getElementsByTagName('info')[0].getAttribute('name') + " " + node.getElementsByTagName('extrainformation')[0].getElementsByTagName('info')[0].childNodes[0].data
                                # Extracts vulnerability description if exists - Description element contains several information splitted & treated separately by this script
                                if node.getElementsByTagName('description')[0].childNodes: 
                                    vuln = re.sub("<.*?>", "", node.getElementsByTagName('description')[0].childNodes[0].data)
                                    vuln = vuln.replace('Impact','&&').replace('Remedy','&&').replace('Impact','&&').replace('External References','&&').replace('Remedy References','&&')
                                    tmp = vuln.split("&&")
                                    # Vulnerability description obtained from 1st splitted data
                                    description = tmp[0]
                                    # Vulnerability impact obtained from 2nd splitted data
                                    if tmp[1].split("Actions to Take"):
                                        impact = re.sub("\t","",tmp[1].split("Actions to Take")[0])
                                    # 3rd splitted data is treated in order to get the vulnerability solution
                                    if len(tmp) > 2:
                                        if tmp[2].split("Required Skills for Successful Exploitation"):
                                            solution = re.sub("\t","",tmp[2].split("Required Skills for Successful Exploitation")[0])
                                        elif tmp[2].split("External References"):
                                            solution = re.sub("\t","",tmp[2].split("External References")[0])
                                        elif tmp[2].split("Remedy References"):
                                            solution = re.sub("\t","",tmp[2].split("Remedy References")[0])
                                # Extracts request if exists
                                if node.getElementsByTagName('rawrequest')[0].childNodes:
                                    request = node.getElementsByTagName('rawrequest')[0].childNodes[0].data
                                # Extracts response if exists
                                if node.getElementsByTagName('rawresponse')[0].childNodes:
                                    response = node.getElementsByTagName('rawresponse')[0].childNodes[0].data
                                # Extracts references from description element if exists
                                if node.getElementsByTagName('description')[0].childNodes:
                                    vuln = node.getElementsByTagName('description')[0].childNodes[0].data
                                    index = 0
                                    while index < len(vuln):
                                        index = vuln.find('<a href="', index)
                                        if index == -1:
                                            break
                                        else:
                                            index += 9
                                            end = vuln.find('">', index)
                                            ref = ref + vuln[index:end] + "\n"
                                # Write all extracted information to Excel report 
                                ws.write(row, 0, vulnerability, self.sVuln)
                                ws.write(row, 1, affected, self.sText)
                                ws.write(row, 2, parameter, self.sText)
                                ws.write(row, 3, detail, self.sText)
                                if "Low" in risk:
                                    ws.write(row, 4, "Low", self.sLow) 
                                elif "Medium" in risk:
                                    ws.write(row, 4, "Medium", self.sMedium) 
                                elif "Important" in risk:
                                    ws.write(row, 4, "High", self.sHigh) 
                                if "Critical" in risk:
                                    ws.write(row, 4, "Critical", self.sCritical) 
                                ws.write(row, 5, description, self.sText)
                                ws.write(row, 6, impact, self.sText)
                                ws.write(row, 7, solution, self.sText)
                                ws.write(row, 8, request, self.sText)
                                ws.write(row, 9, response[0:32767], self.sText)
                                ws.write(row, 12, ref, self.sText)
                                row += 1
                        dom.unlink()
                    except ExpatError:
                        self.printMsg(5, "[!] [Error] Apparently there's a bad XML file"); raise
                    except IndexError:
                        self.printMsg(5, "[!] [Error] A value in the XML file is missing!"); raise
                    except:
                        self.printMsg(5, "[!] [Unexpected Error]"); raise
            del path[0]
            self.netsparker2xls(path, ws, row)
    
    def options(self):
        parser = ArgumentParser(formatter_class=RawTextHelpFormatter,
            epilog='''EXAMPLES: 
            python secutils.py -t Project/Discovery/ -p Project/Enum/
            python secutils.py -rn Project/Discovery/target1 -o Report
            python secutils.py -rN Project/target1/nessus Project/target2/nessus/ -T VulnsDB_Spanish.xls -o Report.xls''')
        
        parser._optionals.title = "MISC"
        parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0')
        parser.add_argument('-o', metavar='OUTPUT-FILE', dest='output', action='append', help='Set an xls output file')
    
        nmapGroup = parser.add_argument_group('NMAP UTILITIES')
        nmapGroup.add_argument('-t', metavar='DIR', nargs='+', dest='pTargets', action='append', help='Create a list of targets from nmap files in xml format located in DIR')
        nmapGroup.add_argument('-p', metavar='DIR', nargs='+', dest='pPorts', action='append', help='Create list of open ports from nmap files in xml format located in DIR')
        nmapGroup.add_argument('-rn', metavar='DIR', nargs='+', dest='pNmap', action='append', help='Create an XLS report from nmap files in xml format located in DIR')
        
        nessusGroup = parser.add_argument_group('NESSUS UTILITIES')
        nessusGroup.add_argument('-rN', metavar='DIR', nargs='+', dest='pNessus', action='append', help='Create an XLS report from .nessus files located in DIR')
        nessusGroup.add_argument('-T', metavar='FILE', dest='dbNessus', action='append', help='Use an xls database FILE to translate nessus reports. Must be used along with -rN')
        
        nessusGroup = parser.add_argument_group('ACUNETIX UTILITIES')
        nessusGroup.add_argument('-ra', metavar='DIR', nargs='+', dest='pAcunetix', action='append', help='Create an XLS report from acunetix files in xml format located in DIR')
        
        nessusGroup = parser.add_argument_group('NETSPARKER UTILITIES')
        nessusGroup.add_argument('-rk', metavar='DIR', nargs='+', dest='pNetsparker', action='append', help='Create an XLS report from netsparker files in xml format located in DIR')        

        if len(sys.argv) == 1:
            return parser.parse_args('--help'.split())
        else:
            return parser.parse_args()
        
if __name__ == '__main__':
    secutils = Secutils()
    print secutils.CYAN + '''
                             __  .__.__          
  ______ ____  ____  __ ___/  |_|__|  |   ______
 /  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
 \___ \\  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
     \/     \/    \/                         \/ 
              - secutils v2.5.1 -
                 c0d3d by zkvL
    ''' + secutils.ENDC

    args = secutils.options()
    try:
        if args.output:
            if args.output[0][-4:] == '.xls':
                secutils.reportName = os.path.abspath(args.output[0])
            else:
                secutils.reportName = os.path.abspath(args.output[0] + '.xls')
                
        if args.pTargets:
            secutils.printMsg(0, "[-] GETTING TARGETS:")
            ft = file("targets.txt","w+")
            targets = secutils.getTargets(secutils.setPath(args.pTargets[0]))
            for t in targets:
                ft.write(t + "\n")
            ft.close()
            secutils.printMsg(4, "[+] targets.txt file successfully created!")
            
        if args.pPorts:
            secutils.printMsg(0, "[-] GETTING PORTS:")
            fp = file("ports.txt","w+")
            ports = secutils.getPorts(secutils.setPath(args.pPorts[0]))
            for i in range(0, len(ports)-1):
                fp.write(ports[i]+",")
            fp.write(ports[-1])
            fp.close
            secutils.printMsg(4, "[+] ports.txt file successfully created!")
            
        if args.pNmap or args.pNessus or args.pAcunetix or args.pNetsparker:
            report, sheet_names = secutils.setWb()
            if args.pNmap:
                secutils.printMsg(0, "[-] NMAP REPORT:")
                if 'Nmap' not in sheet_names:
                    ws = report.add_sheet("Nmap",cell_overwrite_ok=True)     
                    secutils.setTitle(ws, secutils.tNmap, secutils.wNmap)
                    secutils.nmap2xls(secutils.setPath(args.pNmap[0]), ws, 1)
                    secutils.printMsg(4, "[+] Nmap sheet was successfully created into file:\n" +secutils.reportName)
                else:
                    secutils.printMsg(5, "[!] [Error] Duplicate Nmap sheet in workbook " + secutils.reportName.split(secutils.separator)[-1])
            
            if args.pNessus:
                secutils.printMsg(0, "[-] NESSUS REPORT:")
                if 'Nessus' not in sheet_names:
                    ws = report.add_sheet("Nessus",cell_overwrite_ok=True)
                    secutils.setTitle(ws, secutils.tNessus, secutils.wNessus)
                    if args.dbNessus:
                        secutils.nessus2xls(secutils.setPath(args.pNessus[0]), ws, 1, args.dbNessus[0])
                    else:
                        secutils.nessus2xls(secutils.setPath(args.pNessus[0]), ws, 1)
                    secutils.printMsg(4, "[+] Nessus sheet was successfully created into file:\n" +secutils.reportName)
                else:
                    secutils.printMsg(5, "[!] [Error] Duplicate Nessus sheet in workbook " + secutils.reportName.split(secutils.separator)[-1])                    
                    
            if args.pAcunetix:
                secutils.printMsg(0, "[-] ACUNETIX REPORT:")
                if 'Acunetix' not in sheet_names:
                    ws = report.add_sheet("Acunetix",cell_overwrite_ok=True)
                    secutils.setTitle(ws, secutils.tWeb, secutils.wWeb)
                    secutils.acunetix2xls(secutils.setPath(args.pAcunetix[0]), ws, 1)
                    secutils.printMsg(4, "[+] Acunetix sheet was successfully created into file:\n" +secutils.reportName)
                else:
                    secutils.printMsg(5, "[!] [Error] Duplicate Acunetix sheet in workbook " + secutils.reportName.split(secutils.separator)[-1])                    
                    
            if args.pNetsparker:
                secutils.printMsg(0, "[-] NETSPARKER REPORT:")
                if 'Netsparker' not in sheet_names:
                    ws = report.add_sheet("Netsparker",cell_overwrite_ok=True)
                    secutils.setTitle(ws, secutils.tWeb, secutils.wWeb)
                    secutils.netsparker2xls(secutils.setPath(args.pNetsparker[0]), ws, 1)
                    secutils.printMsg(4, "[+] Netsparker sheet was successfully created into file:\n" +secutils.reportName)
                else:
                    secutils.printMsg(5, "[!] [Error] Duplicate Netsparker sheet in workbook " + secutils.reportName.split(secutils.separator)[-1])                    
            report.save(secutils.reportName)
    except IOError:
        secutils.printMsg(5, "[!] [Error] Fail to open necessary files")
    except:
        secutils.printMsg(5, "[!] [Unexpected Error]")
        raise
    
    