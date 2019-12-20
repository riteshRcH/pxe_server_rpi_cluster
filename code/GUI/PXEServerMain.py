import threading
import os
import sys
import SimpleHTTPServer
from cgitb import handler
import SocketServer
from Tkinter import *
import tkMessageBox

try:
    import argparse
except ImportError:
    sys.exit("ImportError: You do not have the Python 'argparse' module installed. Please install the 'argparse' module and try again.")

from time import sleep
from servers import TFTPServer
from servers import DHCPServer
#from servers import HTTPServer

#Default Network Boot File Directory i.e the root directory of TFTP and HTTP Servers
NETBOOT_DIR = 'netboot'

#Default PXE Boot File
NETBOOT_FILE = ''

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


if __name__ == '__main__':          #unit testing
    try:
    	if os.getuid() != 0:
    		tkMessageBox.showwarning("Running as non root user", '\nWARNING: User ID not equal to 0. Not running as root. Servers sockets will probably fail to bind.\n')
    	"""
        #warn the user that they are starting PXE server as non-root user
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

    except KeyboardInterrupt:
        sys.exit('\nShutting down PXE Server...\n')