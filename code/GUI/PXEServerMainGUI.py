import SimpleHTTPServer
import SocketServer
from Tkinter import Tk
from cgitb import handler
import os
import sys
import threading
from time import sleep
import tkMessageBox
import ttk
from Tkinter import *

from servers import DHCPServer
from servers import TFTPServer
from cProfile import label
#from atk import Text
import tkFileDialog


#from servers import HTTPServer
#Default Network Boot File Directory i.e the root directory of TFTP and HTTP Servers
NETBOOT_DIR = 'netboot'

#Default PXE Boot File
NETBOOT_FILE = ''

HTTP_SERVER_PORT = 80
ISO_FILENAME = 'dsl.iso'

#DHCP Default Server Settings
DHCP_SERVER_IP = '192.168.2.2'
DHCP_SERVER_PORT = 67
DHCP_OFFER_BEGIN = '192.168.2.100'
DHCP_OFFER_END = '192.168.2.150'
DHCP_SUBNET = '255.255.255.0'
DHCP_ROUTER_DEFAULT_GW = '192.168.2.1'
DHCP_DNS = '8.8.8.8'
DHCP_BROADCAST = '<broadcast>'
DHCP_FILESERVER = '10.0.0.2'

class GUI:
    def dhcpServerToggle(self):
        if self.v.get()==1:                                                     #DHCP
            self.dhcpServerIPEntry.configure(state='normal') 
            self.dhcpOfferIPRangeBeginEntry.configure(state='normal')   
            self.dhcpOfferIPRangeEndEntry.configure(state='normal')    
            self.dhcpSubnetMaskEntry.configure(state='normal')
            self.dhcpRouterDefaultGatewayEntry.configure(state='normal')
            self.dhcpDNSServerEntry.configure(state='normal')
            self.dhcpFileServerIPEntry.configure(state='normal')            
        elif self.v.get()==2:                                                  #Proxy DHCP
            self.dhcpServerIPEntry.configure(state='disabled') 
            self.dhcpOfferIPRangeBeginEntry.configure(state='disabled')   
            self.dhcpOfferIPRangeEndEntry.configure(state='disabled')    
            self.dhcpSubnetMaskEntry.configure(state='disabled')
            self.dhcpRouterDefaultGatewayEntry.configure(state='disabled')
            self.dhcpDNSServerEntry.configure(state='disabled')
            self.dhcpFileServerIPEntry.configure(state='disabled')
            
    def toggleHTTPServerEnable(self):
        self.httpServerPortEntry.configure(state=('normal' if self.enableHTTPServer.get()==1 else 'disabled'))
    
    def __init__(self):            
        self.root = Tk()
        self.root.title('Portable Computing Environment using Raspberry Pi')
        
        if os.getuid() != 0:
            tkMessageBox.showwarning("Running as non root user", '\nWARNING: User ID not equal to 0. Not running as root. Servers sockets will probably fail to bind.\n')
        
        ######################################################################################
        
        notebook = ttk.Notebook(self.root)
        tab1 = ttk.Frame(notebook);
        tab2 = ttk.Frame(notebook);
        tab3 = ttk.Frame(notebook);
        tab4 = ttk.Frame(notebook);
        tab5 = ttk.Frame(notebook);
        
        ######################################################################################
        
        self.enableIPXE = IntVar()
        self.enableIPXE.set(1)
        self.enableVerboseOutput = IntVar()
        self.enableVerboseOutput.set(0)
        self.enableIPXEChkbtn = Checkbutton(tab1, text = 'Enable iPXE', variable=self.enableIPXE)
        self.enableVerboseOutputChkbtn = Checkbutton(tab1, text = 'Enable verbose Output', variable=self.enableVerboseOutput)
        self.enableIPXEChkbtn.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
        self.enableVerboseOutputChkbtn.grid(row=0, column=1, padx=(10, 10), pady=(5, 5))
        
        ######################################################################################
        
        self.v = IntVar()
        self.v.set(2)
        self.useDHCPServerRbtn = Radiobutton(tab2, text = 'DHCP Server', variable=self.v, value=1, command=self.dhcpServerToggle)
        self.useDHCPProxyServerRbtn = Radiobutton(tab2, text = 'Proxy DHCP Server', variable=self.v, value=2, command=self.dhcpServerToggle)
        self.useDHCPServerRbtn.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
        self.useDHCPProxyServerRbtn.grid(row=0, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpServerIPLabel = Label(tab2, text = 'DHCP Server IP')
        self.dhcpServerIPEntry = Entry(tab2)
        self.dhcpServerIPEntry.insert(0, DHCP_SERVER_IP)
        self.dhcpServerIPEntry.configure(state='disabled')
        self.dhcpServerIPLabel.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpServerIPEntry.grid(row=1, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpOfferIPRangeBeginLabel = Label(tab2, text = 'DHCP Offer IP Range Begin')
        self.dhcpOfferIPRangeBeginEntry = Entry(tab2)
        self.dhcpOfferIPRangeBeginEntry.insert(0, DHCP_OFFER_BEGIN)
        self.dhcpOfferIPRangeBeginEntry.configure(state='disabled')
        self.dhcpOfferIPRangeBeginLabel.grid(row=2, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpOfferIPRangeBeginEntry.grid(row=2, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpOfferIPRangeEndLabel = Label(tab2, text = 'DHCP Offer IP Range End')
        self.dhcpOfferIPRangeEndEntry = Entry(tab2)
        self.dhcpOfferIPRangeEndEntry.insert(0, DHCP_OFFER_END)
        self.dhcpOfferIPRangeEndEntry.configure(state='disabled')
        self.dhcpOfferIPRangeEndLabel.grid(row=3, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpOfferIPRangeEndEntry.grid(row=3, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpSubnetMaskLabel = Label(tab2, text = 'DHCP Subnet mask')
        self.dhcpSubnetMaskEntry = Entry(tab2)
        self.dhcpSubnetMaskEntry.insert(0, DHCP_SUBNET)
        self.dhcpSubnetMaskEntry.configure(state='disabled')
        self.dhcpSubnetMaskLabel.grid(row=4, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpSubnetMaskEntry.grid(row=4, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpRouterDefaultGatewayLabel = Label(tab2, text = 'DHCP Default Gateway IP')
        self.dhcpRouterDefaultGatewayEntry = Entry(tab2)
        self.dhcpRouterDefaultGatewayEntry.insert(0, DHCP_ROUTER_DEFAULT_GW)
        self.dhcpRouterDefaultGatewayEntry.configure(state='disabled')
        self.dhcpRouterDefaultGatewayLabel.grid(row=5, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpRouterDefaultGatewayEntry.grid(row=5, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpDNSServerLabel = Label(tab2, text = 'DHCP DNS Server IP')
        self.dhcpDNSServerEntry = Entry(tab2)
        self.dhcpDNSServerEntry.insert(0, DHCP_DNS)
        self.dhcpDNSServerEntry.configure(state='disabled')
        self.dhcpDNSServerLabel.grid(row=6, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpDNSServerEntry.grid(row=6, column=1, padx=(10, 10), pady=(5, 5))
        
        self.dhcpFileServerIPLabel = Label(tab2, text = 'DHCP File Server IP')
        self.dhcpFileServerIPEntry = Entry(tab2)
        self.dhcpFileServerIPEntry.insert(0, DHCP_FILESERVER)
        self.dhcpFileServerIPEntry.configure(state='disabled')
        self.dhcpFileServerIPLabel.grid(row=7, column=0, padx=(10, 10), pady=(5, 5))
        self.dhcpFileServerIPEntry.grid(row=7, column=1, padx=(10, 10), pady=(5, 5))
        
        ######################################################################################
        
        self.enableTFTPServer = IntVar()
        self.enableTFTPServer.set(1)
        self.enableTFTPServerChkBtn = Checkbutton(tab3, text = 'Enable TFTP', variable=self.enableTFTPServer)
        self.enableTFTPServerChkBtn.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
        
        ######################################################################################
        
        self.enableHTTPServer = IntVar()
        self.enableHTTPServer.set(1)
        self.enableHTTPServerChkBtn = Checkbutton(tab4, text = 'Enable HTTP', variable=self.enableHTTPServer, command=self.toggleHTTPServerEnable)
        self.enableHTTPServerChkBtn.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
        
        self.httpServerPortLabel = Label(tab4, text = 'Port number of HTTP Server')
        self.httpServerPortEntry = Entry(tab4)
        self.httpServerPortEntry.insert(0, HTTP_SERVER_PORT)
        self.httpServerPortLabel.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
        self.httpServerPortEntry.grid(row=1, column=1, padx=(10, 10), pady=(5, 5))
        
        ######################################################################################
        
        global NETBOOT_DIR
        NETBOOT_DIR='netboot'
        self.btnChooseNetBootDir = Button(tab5, text = 'Choose root directory of HTTP and TFTP servers', command=self.getNetBootDir)
        self.showNetBootDirPath = Label(tab5, text='./'+NETBOOT_DIR)
        self.btnChooseNetBootDir.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
        self.showNetBootDirPath.grid(row=0, column=1, padx=(10, 10), pady=(5, 5))
        
        global ISO_FILENAME
        ISO_FILENAME = 'dsl.iso'
        self.btnChooseISO = Button(tab5, text = 'Choose ISO present in above directory', command=self.getISOFileName)
        self.showChosenISOPath = Label(tab5, text='./'+NETBOOT_DIR+"/"+ISO_FILENAME)
        self.btnChooseISO.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
        self.showChosenISOPath.grid(row=1, column=1, padx=(10, 10), pady=(5, 5))
        
        ######################################################################################
        
        notebook.add(tab1, text='General')
        notebook.add(tab2, text='DHCP')
        notebook.add(tab3, text='TFTP')
        notebook.add(tab4, text='HTTP')
        notebook.add(tab5, text='Boot files')
        
        ######################################################################################
        
        notebook.pack(fill=X, padx=(56, 56), pady=(22, 22))
        self.btnStartPXEServer = Button(self.root, text='Start PXE server!', command=self.startPXEServer)
        self.btnStartPXEServer.pack(pady=(22, 22))
        self.root.mainloop()

        """
        #warn the user that they are starting servers as non-root user
        if os.getuid() != 0:
            print '\nWARNING: User ID not equal to 0. Not running as root. Servers sockets will probably fail to bind.\n'
        
        #
        # Define Command Line Arguments
        #

        #main service arguments
        parser = argparse.ArgumentParser(description = 'Set options at runtime. Defaults are in %(prog)s', formatter_class = argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--ipxe', action = 'store_true', dest = 'USE_IPXE', help = 'Enable iPXE ROM', default = False)
        parser.add_argument('--http', action = 'store_true', dest = 'USE_HTTP', help = 'Enable built-in HTTP server', default = False)
        parser.add_argument('--no-tftp', action = 'store_false', dest = 'USE_TFTP', help = 'Disable built-in TFTP server, by default it is enabled', default = True)
        parser.add_argument('--verbose', action = 'store_true', dest = 'MODE_VERBOSE', help = 'Adds verbosity to the selected services while they run', default = False)
        
        #argument group for DHCP server
        exclusive = parser.add_mutually_exclusive_group(required = False)
        exclusive.add_argument('--DHCPServer', action = 'store_true', dest = 'USE_DHCP', help = 'Enable built-in DHCP server', default = False)
        exclusive.add_argument('--DHCPServer-proxy', action = 'store_true', dest = 'DHCP_MODE_PROXY', help = 'Enable built-in DHCP server in proxy mode (implies --DHCPServer)', default = False)
        parser.add_argument('-s', '--DHCPServer-server-ip', action = 'store', dest = 'DHCP_SERVER_IP', help = 'DHCP Server IP', default = DHCP_SERVER_IP)
        parser.add_argument('-p', '--DHCPServer-server-port', action = 'store', dest = 'DHCP_SERVER_PORT', help = 'DHCP Server Port', default = DHCP_SERVER_PORT)
        parser.add_argument('-b', '--DHCPServer-begin', action = 'store', dest = 'DHCP_OFFER_BEGIN', help = 'DHCP lease range start', default = DHCP_OFFER_BEGIN)
        parser.add_argument('-e', '--DHCPServer-end', action = 'store', dest = 'DHCP_OFFER_END', help = 'DHCP lease range end', default = DHCP_OFFER_END)
        parser.add_argument('-n', '--DHCPServer-subnet', action = 'store', dest = 'DHCP_SUBNET', help = 'DHCP lease subnet', default = DHCP_SUBNET)
        parser.add_argument('-r', '--DHCPServer-router', action = 'store', dest = 'DHCP_ROUTER_DEFAULT_GW', help = 'DHCP lease router', default = DHCP_ROUTER_DEFAULT_GW)
        parser.add_argument('-d', '--DHCPServer-dns', action = 'store', dest = 'DHCP_DNS', help = 'DHCP lease DNS server', default = DHCP_DNS)
        parser.add_argument('-c', '--DHCPServer-broadcast', action = 'store', dest = 'DHCP_BROADCAST', help = 'DHCP broadcast address', default = DHCP_BROADCAST)
        parser.add_argument('-f', '--DHCPServer-fileserver', action = 'store', dest = 'DHCP_FILESERVER', help = 'DHCP fileserver IP', default = DHCP_FILESERVER)

        #network boot directory and file name arguments
        parser.add_argument('-a', '--netboot-dir', action = 'store', dest = 'NETBOOT_DIR', help = 'Local file serve directory', default = NETBOOT_DIR)
        parser.add_argument('-i', '--netboot-file', action = 'store', dest = 'NETBOOT_FILE', help = 'PXE boot file name (after iPXE if --ipxe)', default = NETBOOT_FILE)
        parser.add_argument('-hp', '--http-server-port', action = 'store', dest = 'HTTP_SERVER_PORT', help = 'HTTP Server Port num', default = 80)

        #parse the arguments given
        args = parser.parse_args()

        #pass warning to user regarding starting HTTP server without iPXE
        if args.USE_HTTP and not args.USE_IPXE and not args.USE_DHCP:
            print '\nWARNING: HTTP selected but iPXE disabled. PXE ROM must support HTTP requests.\n'
        
        #if the argument was pased to enabled ProxyDHCP then enable the DHCP server
        if args.DHCP_MODE_PROXY:
            args.USE_DHCP = True

        #if the network boot file name was not specified in the argument, set it based on what services were enabled/disabled
        if args.NETBOOT_FILE == '':
            if not args.USE_IPXE:                   #not using IPXE so need pxelinux.0
                args.NETBOOT_FILE = 'pxelinux.0'    
            elif not args.USE_HTTP:                 # not using HTTP so using TFTP therefore boot.ipxe
                args.NETBOOT_FILE = 'boot.ipxe'
            else:                                   #using HTTP therefore boot.http.ipxe
                args.NETBOOT_FILE = 'boot.http.ipxe'

        #serve all files from one directory
        os.chdir (args.NETBOOT_DIR)
        
        #make a list of running threads for each service
        runningServices = []

        #configure/start TFTP server
        if args.USE_TFTP:
            print 'Starting TFTP server...'
            tftpServer = TFTPServer.TFTPServerDaemon(enableVerboseOutput = args.MODE_VERBOSE)
            tftpd = threading.Thread(target = tftpServer.listen)
            tftpd.daemon = True
            tftpd.start()
            runningServices.append(tftpd)

        #configure/start DHCP server
        if args.USE_DHCP:
            if args.DHCP_MODE_PROXY:
                print 'Starting DHCP server in ProxyDHCP mode (DHCP Leases would be given by existing DHCP server)...'
            else:
                print 'Starting DHCP server...'
            dhcpServer = DHCPServer.DHCPServerDaemon(
                    ip = args.DHCP_SERVER_IP,
                    port = args.DHCP_SERVER_PORT,
                    offerFrom = args.DHCP_OFFER_BEGIN,
                    offerTo = args.DHCP_OFFER_END,
                    subnetMask = args.DHCP_SUBNET,
                    routerDefaultGateway = args.DHCP_ROUTER_DEFAULT_GW,
                    dnsServer = args.DHCP_DNS,
                    broadcast = args.DHCP_BROADCAST,
                    tftpServerIP = args.DHCP_FILESERVER,
                    filename = args.NETBOOT_FILE,
                    useipxe = args.USE_IPXE,
                    usehttp = args.USE_HTTP,
                    enableDHCPProxyMode = args.DHCP_MODE_PROXY,
                    enableVerboseOutput = args.MODE_VERBOSE)
            dhcpd = threading.Thread(target = dhcpServer.listen)
            dhcpd.daemon = True
            dhcpd.start()
            runningServices.append(dhcpd)


        #configure/start HTTP server
        if args.USE_HTTP:
            print 'Starting HTTP server on port '+str(args.HTTP_SERVER_PORT)+'..'
            handler = SimpleHTTPServer.SimpleHTTPRequestHandler
            httpd = SocketServer.TCPServer(("", int(args.HTTP_SERVER_PORT)), handler)
            httpd.serve_forever()

        print 'PXE Server successfully initialized and running!'

        while map(lambda x: x.isAlive(), runningServices):
            sleep(1)
            """
            
    def getNetBootDir(self):
    	global NETBOOT_DIR
        NETBOOT_DIR = tkFileDialog.askdirectory(parent=self.root, title="Choose netboot directory", initialdir='/' if NETBOOT_DIR=='netboot' else NETBOOT_DIR)
        self.showNetBootDirPath.config(text=NETBOOT_DIR)
        
    def getISOFileName(self):
    	global ISO_FILENAME
        while True:
            ISO_FILENAME = tkFileDialog.askopenfilename(parent=self.root, title="Please select an iso file", initialdir=NETBOOT_DIR, multiple=False)
            if(ISO_FILENAME.endswith('.iso')):
                break
        self.showChosenISOPath.config(text=ISO_FILENAME)
        
    def startPXEServer(self):
        if self.enableHTTPServer.get()==True and not self.enableIPXE.get()==1 and not self.v.get()==1:
            print '\nWARNING: HTTP selected but iPXE disabled. PXE ROM must support HTTP requests.\n'
            
        global NETBOOT_DIR
        global NETBOOT_FILE
        global ISO_FILENAME
        global DHCP_BROADCAST

        #if the network boot file name was not specified in the argument, set it based on what services were enabled/disabled
        if NETBOOT_FILE == '':
            if not self.enableIPXE.get()==True:                   #not using IPXE so need pxelinux.0
                NETBOOT_FILE = 'pxelinux.0'    
            elif not self.enableHTTPServer.get()==True:                 # not using HTTP so using TFTP therefore boot.ipxe
                NETBOOT_FILE = 'boot.ipxe'
            else:                                   #using HTTP therefore boot.http.ipxe
                NETBOOT_FILE = 'boot.http.ipxe'

        #serve all files from one directory
        os.chdir (NETBOOT_DIR)
        
        #make a list of running threads for each service
        runningServices = []

        #configure/start TFTP server
        if self.enableTFTPServer.get()==True:
            print 'Starting TFTP server...'
            tftpServer = TFTPServer.TFTPServerDaemon(enableVerboseOutput = self.enableVerboseOutput.get()==True)
            tftpd = threading.Thread(target = tftpServer.listen)
            tftpd.daemon = True
            tftpd.start()
            runningServices.append(tftpd)

        #configure/start DHCP server
        if self.v.get()==2:
            print 'Starting DHCP server in ProxyDHCP mode (DHCP Leases would be given by existing DHCP server)...'
        else:
            print 'Starting DHCP server...'
        dhcpServer = DHCPServer.DHCPServerDaemon(
                ip = self.dhcpServerIPEntry.get(),
                port = DHCP_SERVER_PORT,
                offerFrom = self.dhcpOfferIPRangeBeginEntry.get(),
                offerTo = self.dhcpOfferIPRangeEndEntry.get(),
                subnetMask = self.dhcpSubnetMaskEntry.get(),
                routerDefaultGateway = self.dhcpRouterDefaultGatewayEntry.get(),
                dnsServer = self.dhcpDNSServerEntry.get(),
                broadcast = DHCP_BROADCAST,
                tftpServerIP = self.dhcpFileServerIPEntry.get(),
                filename = NETBOOT_FILE,
                useipxe = self.enableIPXE.get()==True,
                usehttp = self.enableHTTPServer.get()==True,
                enableDHCPProxyMode = self.v.get()==2,
                enableVerboseOutput = self.enableVerboseOutput.get()==True)
        dhcpd = threading.Thread(target = dhcpServer.listen)
        dhcpd.daemon = True
        dhcpd.start()
        runningServices.append(dhcpd)

        #configure/start HTTP server
        if self.enableHTTPServer.get()==True:
            print 'Starting HTTP server on port '+str(self.httpServerPortEntry.get())+'..'
            handler = SimpleHTTPServer.SimpleHTTPRequestHandler
            httpd = SocketServer.TCPServer(("", int(self.httpServerPortEntry.get())), handler)
            httpd.serve_forever()

        print 'PXE Server successfully initialized and running!'

        while map(lambda x: x.isAlive(), runningServices):
            sleep(1)
            
if __name__ == '__main__':          #unit testing
    try:
        GUI()
    except KeyboardInterrupt:
        sys.exit('\nShutting down PXE Server...\n')