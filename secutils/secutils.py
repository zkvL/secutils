#!/usr/bin/env python3

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

import os, sys, re, requests
import secutils.nmap as nmap
import secutils.nessus as nessus
from argparse import ArgumentParser, RawTextHelpFormatter
from colorama import init, Fore, Back, Style
from platform import system

current = '3.5.0'
separator = '/'
reportName = os.path.abspath('SecutilsReport.xlsx')

def setPath(path):
	global separator
	if system() == 'Windows':
		separator = '\\'
	
	for i in range(len(path)):
		if  path[i][-1] != separator:
			path[i] = path[i] + separator
	return path

def setOutput(output):
	if output[-5:] == '.xlsx':
		return os.path.abspath(output)
	else:
		return os.path.abspath(output + '.xlsx')

def nmapModule(args):
	module = nmap.Nmap()

	if args.targets:
		separator = '\n'
		print(Fore.YELLOW + "[-] Retrieve alive IPs from nmap output:")
		module.write_nmap_data(module.getTargets(setPath(args.targets[0])), 'targets.txt', separator)
		print(Fore.GREEN + "[+] targets.txt file successfully created!")

	if args.ports:
		separator = ','
		print(Fore.YELLOW + "[-] Retrieve open ports from nmap output")
		module.write_nmap_data(module.getPorts(setPath(args.ports[0])), 'ports.txt', separator)
		print(Fore.GREEN + "[+] ports.txt file successfully created!")

	if args.nmapxlsx:
		global reportName
		if args.output:
			reportName = setOutput(args.output[0])

		# Create the Excel file & set custom format
		print(Fore.YELLOW + "[-] Create Excel report from Nmap outputs:")
		module.report(reportName, setPath(args.nmapxlsx[0]))
		print(Fore.GREEN + "[+] Enumeration sheet was successfully created into file:\n" + reportName + "\n")

def nessusModule(args):
	module = nessus.Nessus()
	global reportName

	if args.output and args.nessusxlsx :
		reportName = setOutput(args.output[0])
	
	if args.nessustxt:
		# Create a simple TXT file report
		print(Fore.YELLOW + "[-] Create simple TXT report from NESSUS outputs:")
		if args.lang:
			module.report(reportName, setPath(args.nessustxt[0]), 1, args.lang)
		else:
			module.report(reportName, setPath(args.nessustxt[0]), 1)
		print(Fore.GREEN + "[+] SecutilsNessusReport txt file successfully created")

	if args.nessusxlsx:
		# Create the Excel file & set custom format
		print(Fore.YELLOW + "[-] Create Excel report from NESSUS outputs:")
		if args.lang:
			module.report(reportName, setPath(args.nessusxlsx[0]), 2, args.lang)
		else:
			module.report(reportName, setPath(args.nessusxlsx[0]), 2)
		print(Fore.GREEN + "[+] Vuln Assessment sheet was successfully created into file:\n" + reportName + "\n")

def checkUpdate():
	try:
		pattern = re.compile(r"##\s\[\d+\.\d+\.\d+\]")
		url = 'https://raw.githubusercontent.com/zkvL7/secutils/master/CHANGELOG.md'
		data = requests.get(url, stream=True)

		lastest = pattern.findall(str(data.content))[0]
		if (current not in lastest):
			print(Fore.YELLOW + Back.BLUE + Style.BRIGHT + "[!] There's an update available at https://github.com/zkvL7/secutils [!]" + Style.RESET_ALL + "\n")
	except:
		print(Fore.RED + "[!] ERROR: Something happend when checking updates")
		pass

def options():
	parser = ArgumentParser(formatter_class=RawTextHelpFormatter,
		epilog='''Examples: 
		secutils nmap --targets Project/Discovery/ --ports Project/Enum/
		secutils namp --report Project/Discovery/target1 -o AwesomeReportName
		secutils nessus -r Project/target1/nessus Project/target2/nessus/ -T spanish -o AwesomeReportName.xlsx''')
	subparsers = parser.add_subparsers(title='Available Modules' ,help='[FLAGS]')

	parser._optionals.title = "Miscellaneous"
	parser.add_argument('-v', '--version', action='version', version=f'secutils {current}')
	parser.add_argument('-k', '--no-check', action='store_true', dest='noupdate', help='Avoid checking for updates')

	nmapParser = subparsers.add_parser("nmap")
	nmapParser.set_defaults(module='nmap')
	nessusParser = subparsers.add_parser("nessus")
	nessusParser.set_defaults(module='nessus')

	nmapGroup = nmapParser.add_argument_group('Nmap Utils')
	nmapGroup.add_argument('-t','--targets', metavar='DIR', nargs='+', dest='targets', action='append', help='Create a list of IP addresses from nmap xml output files from DIR')
	nmapGroup.add_argument('-p','--ports', metavar='DIR', nargs='+', dest='ports', action='append', help='Create a list of open ports from nmap xml output files from DIR')
	nmapGroup.add_argument('-r', '--report', metavar='DIR', nargs='+', dest='nmapxlsx', action='append', help='Create an XLSX report from nmap xml output files from DIR')
	nmapGroup.add_argument('-o','--output', metavar='OUTPUT-FILE', dest='output', action='append', help='Set an XLSX output file')

	nessusGroup = nessusParser.add_argument_group('Nessus Utils')
	nessusGroup.add_argument('-r', '--report', metavar='DIR', nargs='+', dest='nessusxlsx', action='append', help='Create an XLSX report from .nessus files from DIR')
	nessusGroup.add_argument('-s', '--simple-report', metavar='DIR', nargs='+', dest='nessustxt', action='append', help='Create a TXT simple report from .nessus files from DIR')
	nessusGroup.add_argument('-T', '--translate', metavar='LANGUAGE', dest='lang', help='Use an SQLite database to translate nessus reports. Requires --report')
	nessusGroup.add_argument('-o','--output', metavar='OUTPUT-FILE', dest='output', action='append', help='Set an XLSX output file')

	if len(sys.argv) == 1:
		return parser.parse_args('--help'.split())
	else:
		return parser.parse_args()

def main():
	init(autoreset=True)
	print(Fore.CYAN + '''
                           __  .__.__          
______ ____  ____  __ ___/  |_|__|  |   ______
/  ____/ __ _/ ___\|  |  \   __|  |  |  /  ___/
\___ \\  ___\  \___|  |  /|  | |  |  |__\___ \ 
/____  >\___  \___  |____/ |__| |__|____/____  >
   \/     \/    \/                         \/ 
                          - secutils v'''+f'{current}'+''' - 
                                  by @zkvL
  ''')
	args = options()
	if not args.noupdate:
		checkUpdate()

	try:
		if args.module == 'nmap':
			nmapModule(args)
		elif args.module == 'nessus':
			nessusModule(args)
	except:
		print(Fore.RED + "[!] You need to select a module")

if __name__ == '__main__':
	main()	
