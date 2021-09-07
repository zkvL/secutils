#!/usr/bin/env python3

import os, sys, re
import requests
import sqlite3 
import xlsxwriter
from argparse import ArgumentParser, RawTextHelpFormatter
from colorama import init, Fore, Back, Style
from glob import glob
from platform import system
from time import sleep
from tqdm import tqdm
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError

class Spreadsheet:
  # workbook styles 
  stTitle = stText = stVuln = stVulnNF = stCritical = stHigh = stMedium = stLow = None

  def __init__(self, reportName, sheetName):
  	self.wb = self.confWb(xlsxwriter.Workbook(reportName,{'strings_to_urls': False}))
  	self.ws = self.wb.add_worksheet(sheetName)

  def confWb(self, workbook):    
    # setting workbook styles 
    self.stTitle = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'white', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'bg_color': '#434A51', 
    	'border': 1, 
    	'border_color': 
    	'#A6A6A6'})
    self.stText = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'black', 
    	'align': 'left', 
    	'valign': 'top', 
    	'text_wrap': True, 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    self.stTextBold = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'black', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'text_wrap': True, 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    self.stTextRed = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'red', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'text_wrap': True, 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    self.stCritical = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'white', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'bg_color': '#7030A0', 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    self.stHigh = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'white', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'bg_color': '#FF0000', 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    self.stMedium = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'white', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'bg_color': '#FF5F00', 
    	'border': 1, 
    	'border_color': 
    	'#A6A6A6'})
    self.stLow = workbook.add_format({
    	'font_name': 'Calibri', 
    	'font_color': 'white', 
    	'bold': True, 
    	'align': 'left', 
    	'valign': 'top', 
    	'bg_color': '#007CBF', 
    	'border': 1, 
    	'border_color': '#A6A6A6'})
    
    return workbook

  def confWs(self, titles, widths):
    for i in range(len(titles)):
      self.ws.set_column(i, i, widths[i])
      self.ws.write(0, i, titles[i], self.stTitle)

	# def write_xlsx(self, row, *data):
 #    for i in range(len(data)):
 #      self.ws.write(row, i, data[i], self.stTitle)