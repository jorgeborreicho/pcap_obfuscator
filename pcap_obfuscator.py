#!/usr/bin/python3

'''


*****************************************************************************************
Copyright (c) 2017 Jorge Borreicho

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*****************************************************************************************


'''
import sys
import struct
import binascii
import time
import argparse
import random
import re

from PyQt5.QtWidgets import (QWidget, QMainWindow, QGridLayout, QTextEdit, \
    QLineEdit, QToolTip, QPushButton, QApplication, QMessageBox, QLabel, \
    QComboBox, QCheckBox, QAction, qApp, QFileDialog)
from PyQt5.QtGui import (QIcon, QFont)
from PyQt5.QtCore import QCoreApplication

#--------------------------------------------------------
#   USEFUL FUNCTIONS
#--------------------------------------------------------

def mac2str(mac_bytes):
    mac_addr = struct.unpack("!BBBBBB",mac_bytes)
    result = ""
    for i in range(6):
        if len(hex(mac_addr[i])[2:]) == 2:
            result += hex(mac_addr[i])[2:] + ":"
        else:
            result += "0" + hex(mac_addr[i])[2:] + ":"
            
    return result[:-1]

def str2mac(mac_str):
    s_octet = mac_str.split(':')
    
    mac_addr = binascii.unhexlify(s_octet[0]) + binascii.unhexlify(s_octet[1]) + binascii.unhexlify(s_octet[2]) + binascii.unhexlify(s_octet[3]) + binascii.unhexlify(s_octet[4]) + binascii.unhexlify(s_octet[5])
    
    return mac_addr
    
def ip2str(ip_bytes):
    ip_addr = struct.unpack("!BBBB",ip_bytes)
    return str(int(ip_addr[0])) + "." + str(int(ip_addr[1])) + "." + str(int(ip_addr[2])) + "." + str(int(ip_addr[3]))

def str2ip(ip_str):
    s_octet = ip_str.split('.')
    ip_addr = struct.pack('!BBBB',int(s_octet[0]),int(s_octet[1]),int(s_octet[2]),int(s_octet[3]))
    return ip_addr

def ip_match(ip, filter):

#this function matches an IP (string not bytes) against a filter
#for example 10.*.50.* (match any IP with 10 as the 1st octet and 50 as the 3rd octet)

    ip_octets = iter(ip.split("."))
    filter_octets = iter(filter.split("."))

    for filter_octet in filter_octets:   
        ip_octet = next(ip_octets)     
        if filter_octet == '*':
            pass
        elif filter_octet != ip_octet:
            return False
            
    return True

def ip_modify(ip, changes):

#this function changes an IP (string not bytes) with new octets
#for example 192.*.23.* (change the 1st octet to 192 and the 3rd octet to 23)
    
    ip_octets = iter(ip.split("."))
    new_octets = iter(changes.split("."))
    result = []
    
    for new_octet in new_octets:   
        ip_octet = next(ip_octets)  
        
        if new_octet == '*':
            result.append(ip_octet)
        elif int(new_octet) >= 0 and int(new_octet) <= 255:
            result.append(new_octet)
        else:
            result.append(ip_octet)
    
    return '.'.join(result)
            
def mac_match(mac, filter):

#this function matches a MAC address (string not bytes) against a filter
#for example 10:*:50:*:*:* (match any MAC with 10 as the 1st octet and 50 as the 3rd octet)

    mac_octets = iter(mac.split(":"))
    filter_octets = iter(filter.split(":"))

    for filter_octet in filter_octets:   
        mac_octet = next(mac_octets)     
        if filter_octet == '*':
            pass
        elif filter_octet != mac_octet:
            return False
            
    return True

def mac_modify(mac, changes):

#this function changes a MAC address (string not bytes) with new octets
#for example aa:*:cc:*:*:* (change the 1st octet to aa and the 3rd octet to cc)
    
    mac_octets = iter(mac.split(":"))
    new_octets = iter(changes.split(":"))
    result = []
    
    for new_octet in new_octets:   
        mac_octet = next(mac_octets)  
        
        if new_octet == '*':
            result.append(mac_octet)
        else:
            result.append(new_octet)
    
    return ':'.join(result)  

    
#--------------------------------------------------------
#   PCAP Obfuscator
#--------------------------------------------------------     
    
def pcap_obfuscator(input_filename, output_filename, filter, modify, type, payload):  
 
    #output vars
    error = None
    log = ""

    #two random int for type AUTO
    rand1 = random.randint(43, 67)
    rand2 = random.randint(11, 23)
    rand3 = random.randint(100, 119)
    rand4 = random.randint(3, 17)
    
    try:
        ifile = open(input_filename, "rb")
    except:
        error = "Input file access error! Open a PCAP file using the File menu."
        return error, log
    try:    
        ofile = open(output_filename, "wb")
    except:
        error = "Output file write error! Please indicate the filename using the full path."
        return error, log
        
    #read global header from original pcap file
    global_header = ifile.read(24)
    
    #decode the glocal header (not realy necessary if we do not change it...)
    pcap_magic_n, pcap_ver1, pcap_ver2, pcap_timezone, \
    pcap_accuracy, pcap_max_packet_len, pcap_link_layer_type = struct.unpack("<IHHIIII",global_header)
    
    #write global header to the output pcap file
    ofile.write(global_header)
    
    #log global header

    log += "\n-------- Global Header --------\n"
    log += "\nMagic Number: " + str(pcap_magic_n)
    log += "\nVersion: " + str(pcap_ver1) + "." + str(pcap_ver2)
    log += "\nTimezone: " +str(pcap_timezone)
    log += "\nAccuracy: " +str(pcap_accuracy)
    log += "\nMax. Packet Length: " +str(pcap_max_packet_len)
    log += "\nLink-Layer Type: " +str(pcap_link_layer_type)

    
    pcap_packet_n = 0 #packet number
    
    while len(ifile.read(16)) == 16:#each packet in the file has a 16 byte header (a good way to find if there are more packets to read)
    
        pcap_packet_n += 1
        ifile.seek(ifile.tell()-16)#go back 16 bytes to decode packet header
        pcap_packet_header = ifile.read(16)
        pcap_packet_ts, pcap_packet_us, pcap_packet_len, pcap_packet_wirelen = struct.unpack("<IIII",pcap_packet_header)
                
        #read the actual packet bytes
        pcap_packet = ifile.read(pcap_packet_len)
        
        if pcap_link_layer_type == 1: #check if link layer is Ethernet
            src_mac = mac2str(pcap_packet[0:6])
            dst_mac = mac2str(pcap_packet[6:12])
            eth_type = struct.unpack("!H",pcap_packet[12:14])[0]
                
            new_src_mac = None
            new_dst_mac = None
            new_vlan_id = None
            
            vlan_offset = 0 #needed when the packet is tagged with 802.1Q 
            
            #modify MAC addresses using random variables
            if type == "AUTO":
                if src_mac != "ff:ff:ff:ff:ff:ff": #avoid changing broadcast addresses
                    new_src_mac = mac_modify(src_mac, "*:*:*:" + str(rand1) + ":" + str(rand2) + ":*")
                    pcap_packet = str2mac(new_src_mac) + pcap_packet[6:]
                if dst_mac != "ff:ff:ff:ff:ff:ff": #avoid changing broadcast addresses
                    new_dst_mac = mac_modify(dst_mac, "*:*:*:" + str(rand1) + ":" + str(rand2) + ":*")
                    pcap_packet = pcap_packet[:6] + str2mac(new_dst_mac) + pcap_packet[12:]
               
            #modify MAC addresses that match the filter criteria with new octet value
            if type == "MAC" and mac_match(src_mac, filter):
                new_src_mac = mac_modify(src_mac, modify)
                pcap_packet = str2mac(new_src_mac) + pcap_packet[6:] 
                
            if type == "MAC" and mac_match(dst_mac, filter):
                new_dst_mac = mac_modify(dst_mac, modify)
                pcap_packet = pcap_packet[:6] + str2mac(new_dst_mac) + pcap_packet[12:]             
            
            if eth_type == 33024: #"\x81\x00" = 33024 that means 802.1Q is the upper layer
                
                vlan_id = int(struct.unpack("!H",pcap_packet[14:16])[0] & 4095) # VLAN ID is coded in the 12 least significant bits
                prio_and_dei = struct.unpack("!H",pcap_packet[14:16])[0] & 28672 #Priority Code Point and Drop Eligible Indicator in the 3 most significant bits
                eth_type = struct.unpack("!H",pcap_packet[16:18])[0]
                

                
                if type == "VLAN" and vlan_id == int(filter):
                    if int(modify) > 0 and int(modify) <= 4094:
                        new_vlan_id = int(modify)
                        pcap_packet = pcap_packet[:14] + struct.pack("!H", int(prio_and_dei) + int(modify)) + pcap_packet[16:]
                    else:
                        error = "VLAN error! Please set VLAN ID between 1 to 4094."
                        return error, log
                if type == "AUTO":
                        new_vlan_id = int(vlan_id / 2) + rand4
                        pcap_packet = pcap_packet[:14] + struct.pack("!H", int(prio_and_dei) + new_vlan_id) + pcap_packet[16:]
                        
                vlan_offset += 4 #802.1Q header is 4 bytes long
                
            if eth_type == 2048: #"\x08\x00" = 2048 that means IP is the upper layer
                src_ip = ip2str(pcap_packet[26+vlan_offset:30+vlan_offset])
                dst_ip = ip2str(pcap_packet[30+vlan_offset:34+vlan_offset])
                ip_length = struct.unpack("!H",pcap_packet[16+vlan_offset:18+vlan_offset])[0]
                ip_protocol = struct.unpack("!B",pcap_packet[23+vlan_offset:24+vlan_offset])[0]
              
                new_src_ip = None
                new_dst_ip = None
                
                #modify IP addresses using random variables
                if type == "AUTO":
                    new_src_ip = ip_modify(src_ip, "10." + str(rand3) + ".*.*")
                    new_dst_ip = ip_modify(dst_ip, "10." + str(rand3) + ".*.*")
                    pcap_packet = pcap_packet[:26+vlan_offset] + str2ip(new_src_ip) + pcap_packet[30+vlan_offset:]
                    pcap_packet = pcap_packet[:30+vlan_offset] + str2ip(new_dst_ip) + pcap_packet[34+vlan_offset:]
                    
                #modify IP addresses that match the filter criteria with new octet values
                if type == "IP" and ip_match(src_ip, filter):
                    new_src_ip = ip_modify(src_ip, modify)
                    pcap_packet = pcap_packet[:26+vlan_offset] + str2ip(new_src_ip) + pcap_packet[30+vlan_offset:] 
                    
                if type == "IP" and ip_match(dst_ip, filter):
                    new_dst_ip = ip_modify(dst_ip, modify)  
                    pcap_packet = pcap_packet[:30+vlan_offset] + str2ip(new_dst_ip) + pcap_packet[34+vlan_offset:] 
            

            
            
            pcap_packet_len_offset = 0
            
            #try to ofuscate IP addresses in text based payloads when -p option is set

            if payload and eth_type == 2048:
                
                #find IP-like strings in packet payload (works with text based protocols like SIP, HTTP,... but not with GTP, MAP,...)
                re_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                packet_payload = pcap_packet[34+vlan_offset:]
                
                pcap_packet_len_offset = 0
                for ip_match_obj in re_ip.finditer(str(packet_payload)):#returns an iterator over MatchObject objects
                    
                    #for each IP-like string found modify it accordingly
                    old_ip = str(packet_payload)[ip_match_obj.start():ip_match_obj.end()]
                    
                    if type == "IP" and ip_match(old_ip,filter):  
                        new_ip = ip_modify(old_ip, modify)
                    elif  type == "AUTO":
                        new_ip = ip_modify(old_ip, "10." + str(rand3) + ".*.*")
                    else:
                        continue

                    s = pcap_packet.find(old_ip.encode("utf-8"))
                    e = s + len(old_ip.encode("utf-8"))
                    
                    #replace the old IP with the new IP in the packet
                    pcap_packet = pcap_packet[:s] + new_ip.encode("utf-8") + pcap_packet[e:] 
                    pcap_packet_len_offset += (len(new_ip.encode("utf-8")) - len(old_ip.encode("utf-8")))#needed to ajust pcap packet header

                #adjust packet length in pcap packet header
                pcap_packet_header = struct.pack("<IIII",pcap_packet_ts, pcap_packet_us, pcap_packet_len + pcap_packet_len_offset, pcap_packet_wirelen + pcap_packet_len_offset)
                
                #adjust packet length in IP header
                struct.pack("!H", ip_length + pcap_packet_len_offset)
                pcap_packet =  pcap_packet[:16+vlan_offset] + struct.pack("!H", ip_length + pcap_packet_len_offset) + pcap_packet[18+vlan_offset:]
                
                #adjust packet UDP header if L4 is UDP(17)
                if ip_protocol == 17:
                    udp_length = struct.unpack("!H",pcap_packet[38:40])[0]
                    pcap_packet = pcap_packet[:38+vlan_offset] + struct.pack("!H", udp_length  + pcap_packet_len_offset) + pcap_packet[40+vlan_offset:]
                
                
            #write packet header to the output pcap file
            ofile.write(pcap_packet_header)
            
            #write packet (with or without modifications) to output pcap file        
            ofile.write(pcap_packet)    
            
            #log packet header
            log += "\n\n-------- Packet " + str(pcap_packet_n) +  " --------\n"
            log += "\nTimestamp: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap_packet_ts)) + "." + str(pcap_packet_us)
            log += "\nLength: " + str(pcap_packet_len) + " (" + str(pcap_packet_len_offset) + " after modification)"            

            if new_src_mac is not None:
                log += "\nSrc MAC: " + src_mac + " -- modified --> " + new_src_mac
            else:
                log += "\nSrc MAC: " + src_mac
            if new_dst_mac is not None:
                log += "\nDst MAC: " + dst_mac + " -- modified --> " + new_dst_mac
            else:
                log += "\nDst MAC: " + dst_mac
            if vlan_offset == 4 and new_vlan_id is None:
                log += "\nVLAN ID: " + str(vlan_id)
            if vlan_offset == 4 and new_vlan_id is not None:
                log += "\nVLAN ID: " + str(vlan_id) + " -- modified --> " + str(new_vlan_id)
            if new_src_ip is not None:
                log += "\nSrc IP: " + src_ip + " -- modified --> " + new_src_ip
            else:
                log += "\nSrc IP: " + src_ip
            if new_dst_ip is not None:
                log += "\nDst IP: " + dst_ip + " -- modified --> " + new_dst_ip
            else:
                log += "\nDst IP: " + dst_ip  
                
            if payload:
                log += "\nPayload was probably also modified."

    ifile.close()
    ofile.close()
    
    return error, log
    
#--------------------------------------------------------
#   GUI
#-------------------------------------------------------- 

class LogWindow(QMainWindow):  

    def __init__(self):
        super().__init__()
      
        self.button_map = dict()
        
        self.initUI()
        
        
    def initUI(self):
        self.text_log = QTextEdit()
        
        self.button_clear_log = QPushButton('Clear Log', self)
        self.button_clear_log.resize(self.button_clear_log.sizeHint())
        self.button_clear_log.clicked.connect(self.buttonHandler)  
        self.button_map[self.button_clear_log] = "clear_log"
        
        self.grid = QGridLayout()
        self.grid.setSpacing(10)
        self.grid.addWidget(self.text_log, 0, 0, 5, 3)
        self.grid.addWidget(self.button_clear_log, 5, 2, 1, 1)
        
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.grid)
           
        #Window
        self.setCentralWidget(self.central_widget)
        self.setGeometry(800, 300, 500, 500)
        self.setWindowTitle('PCAP Obfuscator Log')
        self.setWindowIcon(QIcon('LisboaAppsIcon.png'))
        
    def buttonHandler(self):
        action = self.button_map[self.sender()]
        if action == "clear_log":
            self.text_log.clear()
            
    def log(self, text): 
        self.text_log.insertPlainText(text)
        
class HelpWindow(QMainWindow):  

    def __init__(self):
        super().__init__()
   
        self.initUI()
        
        
    def initUI(self):

        newfont = QFont("Arial", 10, QFont.Bold)
        
        self.instructions1 = QLabel('Quick Guide')
        self.instructions1.setFont(newfont)
        
        self.instructions2 = QLabel('Input filename:')
        self.instructions3 = QLabel('Fill in using the full path or use File -> Open.')
        self.instructions4 = QLabel('Output filename:')
        self.instructions5 = QLabel('Fill in using the full path. Hint: use File -> Open first get the path.')
        self.instructions6 = QLabel('Filter:')
        self.instructions7 = QLabel('Use this field to filter and select which packets get modified.')       
        self.instructions8 = QLabel('10.*.50.* matches any IP with 10 as the 1st octet and 50 as the 3rd octet.') 
        self.instructions9 = QLabel('10:*:50:*:*:* matches any MAC with 10 as the 1st octet and 50 as the 3rd octet.')
        self.instructions10 = QLabel('1102 matches this VLAN ID.')         
        self.instructions11 = QLabel('Modify:')
        self.instructions12 = QLabel('Use this field to define octet values for IP and MAC addresses.')       
        self.instructions13 = QLabel('192.*.23.* modifies the 1st octet to 192 and the 3rd octet to 23.') 
        self.instructions14 = QLabel('aa:*:cc:*:*:* modifies the 1st octet to aa and the 3rd octet to cc.')
        self.instructions15 = QLabel('102 modifies the VLAN ID to 102.')
        self.instructions16 = QLabel('Type:')
        self.instructions17 = QLabel('AUTO - Both IPs and MACs get obfuscated using random octets (try this option first).')       
        self.instructions18 = QLabel('IP - Filter and modify only at the IP layer (3).') 
        self.instructions19 = QLabel('MAC - Filter and modify only at the MAC layer (2).')
        self.instructions20 = QLabel('VLAN - Filter and modify only the VLAN ID (802.1Q).')
        self.instructions21 = QLabel('Check Payload:')
        self.instructions22 = QLabel('Try to obfuscate IP addresses in text based payloads (e.g. SIP, HTTP, ...)')   
        
        self.grid = QGridLayout()
        self.grid.setSpacing(8)
        self.grid.addWidget(self.instructions1, 0, 0, 1, 1)
        self.grid.addWidget(self.instructions2, 2, 0, 1, 1)
        self.grid.addWidget(self.instructions3, 3, 1, 1, 1)
        self.grid.addWidget(self.instructions4, 4, 0, 1, 1)
        self.grid.addWidget(self.instructions5, 5, 1, 1, 1)
        self.grid.addWidget(self.instructions6, 6, 0, 1, 1)
        self.grid.addWidget(self.instructions7, 7, 1, 1, 1)
        self.grid.addWidget(self.instructions8, 8, 1, 1, 1)
        self.grid.addWidget(self.instructions9, 9, 1, 1, 1)
        self.grid.addWidget(self.instructions10, 10, 1, 1, 1)
        self.grid.addWidget(self.instructions11, 11, 0, 1, 1)
        self.grid.addWidget(self.instructions12, 12, 1, 1, 1)
        self.grid.addWidget(self.instructions13, 13, 1, 1, 1)
        self.grid.addWidget(self.instructions14, 14, 1, 1, 1)
        self.grid.addWidget(self.instructions15, 15, 1, 1, 1)
        self.grid.addWidget(self.instructions16, 16, 0, 1, 1)
        self.grid.addWidget(self.instructions17, 17, 1, 1, 1)  
        self.grid.addWidget(self.instructions18, 18, 1, 1, 1)
        self.grid.addWidget(self.instructions19, 19, 1, 1, 1)  
        self.grid.addWidget(self.instructions20, 20, 1, 1, 1)
        self.grid.addWidget(self.instructions21, 21, 0, 1, 1) 
        self.grid.addWidget(self.instructions22, 22, 1, 1, 1) 
        
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.grid)
           
        #Window
        self.setCentralWidget(self.central_widget)
        self.setGeometry(800, 300, 400, 250)
        self.setWindowTitle('PCAP Obfuscator Help')
        self.setWindowIcon(QIcon('LisboaAppsIcon.png'))
        
                
class MainWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()  
        
        self.button_map = dict()
        self.initUI()
               
    def initUI(self):
       
        #Menu Bar
        action_open = QAction('&Open', self)        
        action_open.setShortcut('Ctrl+O')
        action_open.setStatusTip('Open')
        action_open.triggered.connect(self.openFile)
        
        action_quit = QAction('&Exit', self)        
        action_quit.setShortcut('Ctrl+Q')
        action_quit.setStatusTip('Exit application')
        action_quit.triggered.connect(qApp.quit)
        
        action_show_log_window = QAction('&Log', self)        
        action_show_log_window.setShortcut('Ctrl+L')
        action_show_log_window.setStatusTip('Open Log Window')
        action_show_log_window.triggered.connect(self.openLogWindow)
        
        action_show_help_window = QAction('&Help', self)        
        action_show_help_window.setShortcut('Ctrl+H')
        action_show_help_window.setStatusTip('Open Help Window')
        action_show_help_window.triggered.connect(self.openHelpWindow)
        
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        viewMenu = menubar.addMenu('&View')
        helpMenu = menubar.addMenu('&Help')
        
        fileMenu.addAction(action_open)
        fileMenu.addAction(action_quit)
        viewMenu.addAction(action_show_log_window)
        helpMenu.addAction(action_show_help_window)
        
        #Widgets
        
        self.input_filename_label = QLabel('Input Filename')
        self.input_filename = QLineEdit()
        self.input_filename.setText("")
        
        self.output_filename_label = QLabel('Output Filename')
        self.output_filename = QLineEdit()
        self.output_filename.setText("")
        
        self.filter_label = QLabel('Filter')
        self.filter = QLineEdit()
        self.filter.setText("< AUTO >")       
        
        self.modify_label = QLabel('Modify')
        self.modify = QLineEdit()
        self.modify.setText("< AUTO >")  
        
        self.type_label = QLabel('Type')
        self.type = QComboBox()
        self.type.addItem("AUTO") 
        self.type.addItem("IP") 
        self.type.addItem("MAC") 
        self.type.addItem("VLAN")
        self.type.currentIndexChanged.connect(self.comboBoxChange)
        
       
        self.payload_label = QLabel('Check Payload')
        self.payload = QCheckBox()

        
        self.button_run = QPushButton('Run', self)
        self.button_run.resize(self.button_run.sizeHint())
        self.button_run.clicked.connect(self.buttonHandler)  
        self.button_map[self.button_run] = "run"
        
        self.grid = QGridLayout()
        self.grid.setSpacing(10)
        self.grid.addWidget(self.input_filename_label, 0, 0, 1, 1)
        self.grid.addWidget(self.input_filename, 0, 1, 1, 3)
        self.grid.addWidget(self.output_filename_label, 1, 0, 1, 1)
        self.grid.addWidget(self.output_filename, 1, 1, 1, 3)
        self.grid.addWidget(self.filter_label, 2, 0, 1, 1)
        self.grid.addWidget(self.filter, 2, 1, 1, 3)
        self.grid.addWidget(self.modify_label, 3, 0, 1, 1)
        self.grid.addWidget(self.modify, 3, 1, 1, 3)
        self.grid.addWidget(self.type_label, 4, 0, 1, 1)
        self.grid.addWidget(self.type, 4, 1, 1, 1)
        self.grid.addWidget(self.payload_label, 5, 0, 1, 1)
        self.grid.addWidget(self.payload, 5, 1, 1, 1)
        self.grid.addWidget(self.button_run, 5, 3, 1, 1)
        
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.grid)
           
        #MainWindow
        self.setCentralWidget(self.central_widget)
        self.setGeometry(300, 300, 400, 250)
        self.setWindowTitle('PCAP Obfuscator')
        self.setWindowIcon(QIcon('LisboaAppsIcon.png'))
        
        self.show()
        
        #LogWindow
        self.log_window = LogWindow()
        
        #HelpWindow
        self.help_window = HelpWindow()
        
    def buttonHandler(self):
        action = self.button_map[self.sender()] 
        if action == "run":
            error, log = pcap_obfuscator(self.input_filename.text(), self.output_filename.text(), self.filter.text(), self.modify.text(), self.type.currentText(), self.payload.checkState())
            self.log_window.log(log)
            
            if error == None:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("PCAP obfuscation complete!")
                msg.setInformativeText(self.output_filename.text() + " created.")
                msg.setWindowTitle("PCAP Obfuscator")
                msg.setStandardButtons(QMessageBox.Ok)
                msg.exec_()
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)
                msg.setText("An error occurred.")
                msg.setInformativeText(error)
                msg.setWindowTitle("PCAP Obfuscator")
                msg.setStandardButtons(QMessageBox.Ok)
                msg.exec_() 
                
    def comboBoxChange(self):
        if self.type.currentText() == "IP":
            self.filter.setText("*.*.*.*")
            self.modify.setText("")
        elif self.type.currentText() == "MAC":
            self.filter.setText("*:*:*:*:*:*")
            self.modify.setText("")         
        elif self.type.currentText() == "VLAN":
            self.filter.setText("")
            self.modify.setText("")
        elif self.type.currentText() == "AUTO":
            self.filter.setText("< AUTO >")    
            self.modify.setText("< AUTO >")
            
    def openFile(self, *filename):
        options = QFileDialog.Options()
        self.open_filename, _ = QFileDialog.getOpenFileName(self,"Open PCAP File", "","PCAP Files (*.pcap);;All Files (*)", options=options)
        self.input_filename.setText(self.open_filename)
        self.output_filename.setText(self.open_filename.rsplit('/', 1)[0] + "/obfuscated.pcap")
    
    def openLogWindow(self):
        self.log_window.show()

    def openHelpWindow(self):
        self.help_window.show()  
        
    def closeEvent(self, event):
        
        reply = QMessageBox.question(self, 'Message',
            "Are you sure to quit?", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.log_window.close()
            self.help_window.close()
            event.accept() 
        else:
            event.ignore()    
    
#--------------------------------------------------------
#   MAIN
#--------------------------------------------------------   
def main():
    
    app = QApplication(sys.argv)
    main = MainWindow()
    sys.exit(app.exec_()) 
    
 
if __name__ == "__main__":
    main()
    
