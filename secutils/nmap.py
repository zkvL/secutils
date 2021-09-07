#!/usr/bin/env python3

import os
import secutils.report as report
from colorama import init, Fore, Back, Style
from glob import glob
from platform import system
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError

class Nmap:
  separator = '/'
  def __init__(self):
    if system() == 'Windows':
      self.separator = '\\'

  def write_nmap_data(self, data, filename, separator):
    with open(filename,"w+") as file:
      for i in range(len(data)-1):
        file.write(data[i]+separator)
      file.write(data[-1])

  def getTargets(self, path):
    targets = list()
    # Recursively processes all nmap XML files from all specified folders 
    if len(path) > 0:
      # Obtains all nmap XML files from each folder
      p = path[0] + '*.xml'
      if (len(glob(p)) == 0):
        print(Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5])
      else:    
        for f in glob(p):
          print(Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ...") 
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
    # Recursively processes all nmap XML files from all specified folders 
    if len(path) > 0:
      # Obtains all nmap XML files from each folder
      p = path[0] + '*.xml'
      if (len(glob(p)) == 0):
        print(Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5])
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

  def report(self, reportName, path):
    rpt = report.Spreadsheet(reportName, 'Nmap Report')
    rpt.confWs([
      'IP', 
      'Hostname', 
      'Port', 
      'Protocol', 
      'Service', 
      'Device', 
      'Detail', 
      'O.S.', 
      'Host scripts'], 
      [15, 20, 7, 10, 15, 35, 65, 35, 65])
    self.nmap2xls(path, 1, rpt)
    rpt.wb.close()

  def nmap2xls(self, path, row, rpt): 
    # Recursively processes all nmap XML files from all specified folders 
    if len(path) > 0:
      # Obtains all nmap XML files from each folder
      p = path[0] + '*.xml'
      if (len(glob(p)) == 0):
        Fore.RED + "[!] [ERROR] There's no xml files in " + p[:-5]
      else:
        for f in glob(p):
          print(Fore.CYAN + "Processing " + f.split(self.separator)[-1] + " ...") 
          try:
            dom = parse(f)
            nmaprun = dom.documentElement
            # For each host in nmap XML file retrieves all associated information if host is up
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
                      # Extracts service & all associated information if any 
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
                      rpt.ws.write(row, 0, ip, rpt.stText)
                      rpt.ws.write(row, 1, hostname, rpt.stText)
                      rpt.ws.write(row, 2, port, rpt.stText)
                      rpt.ws.write(row, 3, protocol, rpt.stText)
                      rpt.ws.write(row, 4, service, rpt.stText)
                      rpt.ws.write(row, 5, product+" "+version+" "+extrainfo, rpt.stText)
                      rpt.ws.write(row, 6, detail, rpt.stText)
                      rpt.ws.write(row, 7, os, rpt.stText)
                      rpt.ws.write(row, 8, '', rpt.stText)
                      row += 1
                # Check if scanning has run with scripts
                if node.getElementsByTagName('hostscript'):
                  hscript = ""
                  for script in node.getElementsByTagName('hostscript')[0].getElementsByTagName('script'):
                    hscript = hscript + script.getAttribute('id') + "\n" + script.getAttribute('output') + "\n\n"
                  if (row - hostrow) > 1:
                    rpt.ws.merge_range(hostrow, 8, row-1, 8, hscript, rpt.stText)
            dom.unlink()
          except ExpatError:
              print(Fore.RED + "[!] [ERROR] Apparently there's a bad XML file"); raise
          except IndexError:
              print(Fore.RED + "[!] [ERROR] A value in the XML file is missing!"); raise
          except:
              print(Fore.RED + "[!] [Unexpected Error]"); raise
      del path[0]
      self.nmap2xls(path, row, rpt)
    else:
      rpt.ws.autofilter(0, 0, row-1, 8)