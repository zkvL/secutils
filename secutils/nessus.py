#!/usr/bin/env python3

import os, requests
import secutils.report as report
import sqlite3 
from colorama import init, Fore, Back, Style
from glob import glob
from platform import system
from tqdm import tqdm
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError

class Nessus:
  separator = '/'
  def __init__(self):
    init(autoreset=True)
    if system() == 'Windows':
      self.separator = '\\'

  def download_db(self, lang):
    if os.path.exists(lang+".db"):
      print(Fore.GREEN + "[+] %s database already downloaded" % (lang))
    else:
      print(Fore.CYAN + "Downloading lastest version of %s database ..." % (lang))
      url = "https://github.com/zkvL7/secutils/raw/master/VulnsDBs/"+lang+".db"

      if (requests.head(url, allow_redirects=True)).status_code == 200:
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        block_size = 256
      
        progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True)
        with open(lang+'.db','wb') as db:
          for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            db.write(data)
        progress_bar.close()
        
        if (total_size != 0 and progress_bar.n != total_size):
          print(Fore.RED + "[!] [ERROR] Something failed when downloading db file"); raise
          return False
      else:
        print(Fore.RED + "[!] [ERROR] The DB file does not exists, language not supported yet")
        return False
    return True

  def getVulnT(self, c, id):
    vuln = c.execute('SELECT * FROM vulns WHERE "NessusID"=(?)', (id,)).fetchone()
    return vuln

  def report(self, reportName, path, *args):
    cursor = None
    if len(args) == 2:
      # Downloads the lang.db SQLite file and open the database
      if self.download_db(args[1]):
        db_conn = sqlite3.connect(args[1]+'.db')
        cursor = db_conn.cursor()

    if args[0] == 1:
      if len(args) == 2 and cursor:
        self.extractVulns(path, args[0], cursor)
        db_conn.close()
      else:
        self.extractVulns(path, args[0])
    
    elif args[0] == 2:
      rpt = report.Spreadsheet(reportName, 'Nessus Report')
      rpt.confWs([
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
        'References'],
        [15, 30, 10, 15, 10, 10, 10, 80, 80, 15, 15, 80, 40])

      if len(args) == 2 and cursor:
        self.extractVulns(path, args[0], 1, rpt, cursor)
        db_conn.close()
      else:
        self.extractVulns(path, args[0], 1, rpt)  
      rpt.wb.close()

  def nessus2xlsx(self, rpt, row, found, *data):
    rpt.ws.write(row, 0, data[0], rpt.stText)
    if found:
      rpt.ws.write(row, 1, data[1], rpt.stTextBold)
    else:
      rpt.ws.write(row, 1, data[1], rpt.stTextRed)
    if data[2] == "1":
      rpt.ws.write(row, 2, "Low", rpt.stLow)
    if data[2] == "2":
      rpt.ws.write(row, 2, "Medium", rpt.stMedium)
    if data[2] == "3":
      rpt.ws.write(row, 2, "High", rpt.stHigh)
    if data[2] == "4":
      rpt.ws.write(row, 2, "Critical", rpt.stCritical)
    rpt.ws.write(row, 3, data[3], rpt.stText)
    rpt.ws.write(row, 4, data[4], rpt.stText)
    rpt.ws.write(row, 5, data[5], rpt.stText)
    rpt.ws.write(row, 6, data[6], rpt.stText)
    rpt.ws.write(row, 7, data[7], rpt.stText)
    rpt.ws.write(row, 8, data[8], rpt.stText)
    rpt.ws.write(row, 9, data[9], rpt.stText)
    rpt.ws.write(row, 10, data[10], rpt.stText)
    rpt.ws.write(row, 11, data[11][0:32767], rpt.stText)
    rpt.ws.write_string(row, 12, data[12], rpt.stText)

  def nessus2txt(self, *data):
    with open('SecutilsNessusReport.txt',"a+") as file:
      file.write('-' * 64 + '\n')
      file.write('Title: ' + data[0] + '\n')
      file.write('-' * 64 + '\n')
      file.write('Plugin ID: \t' + data[1] + '\n')
      if data[2] == "1":
        file.write('Risk: \tLow\n')
      elif data[2] == "2":
        file.write('Risk: \tMedium\n')
      elif data[2] == "3":
        file.write('Risk: \tHigh\n')
      elif data[2] == "4":
        file.write('Risk: \tCritical\n')
      file.write('Affected item: \t' + data[3] + '\n')
      file.write('Affected service: \t' + data[4] + ' on port ' + data[5] + '/' + data[6] + '\n')
      file.write('Description: \n\t' + data[7].replace('\n','\n\t') + '\n')
      file.write('Solution: \n\t' + data[8].replace('\n','\n\t') + '\n')
      file.write(data[9] + '\n')
      file.write(data[10] + '\n')
      file.write('Plugin output: \n\t' + data[11] + '\n')
      file.write('References: \n\t' + data[12].replace('\n','\n\t') + '\n')

  def extractVulns(self, path, reptype, *args):
    if reptype == 2:
      row = args[0]
      rpt = args[1]
    # Recursively proceesses all nessus files from all specified folders
    if len(path) > 0:
      # Obtains all nessus files from each folder
      p = path[0] + '*.nessus'
      if (len(glob(p)) == 0):
        print(Fore.RED + "[!] [ERROR] There's no nessus files in " + p[:-8])
      else:
        for f in glob(p):
          print(Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ...") 
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
                  lang_vuln = []
                  if reptype == 2 and len(args) == 3:
                    lang_vuln = self.getVulnT(args[2], int(pluginID))
                  elif reptype == 1 and len(args) == 1:
                    lang_vuln = self.getVulnT(args[0], int(pluginID))
                  if lang_vuln:
                    found = True
                    vulnerability = lang_vuln[1]
                    description = lang_vuln[2]
                    solution = lang_vuln[3]

                  # Write all extracted information to XLSX report if selected
                  if reptype == 2:
                    self.nessus2xlsx(rpt, row, found, pluginID, vulnerability, risk, ip, port, service, protocol, description, solution, cve, cvss, output, ref,)
                    row += 1
                  # Write all extracted information to TXT simple report if selected
                  elif reptype == 1:
                    self.nessus2txt(vulnerability, pluginID, risk, ip, service, port, protocol, description, solution, cve, cvss, output, ref)
            dom.unlink()
          except ExpatError:
            print(Fore.RED + "[!] [ERROR] Apparently there's a bad XML file"); raise
          except IndexError:
            print(Fore.RED + "[!] [ERROR] A value in the XML file is missing!"); raise
          except:
            print(Fore.RED + "[!] [Unexpected Error]"); raise
      del path[0]
      if reptype == 2 and len(args) == 3:
        self.extractVulns(path, reptype, row, rpt, args[2])
      elif reptype == 2 and len(args) == 2:
        self.extractVulns(path, reptype, row, rpt)
      elif reptype == 1 and len(args) == 1:
        self.extractVulns(path, reptype, args[0])
      elif reptype == 1 and not args:
        self.extractVulns(path, reptype)
    if len(path) == 0 and reptype == 2:
      rpt.ws.autofilter(0, 0, row-1, 11)