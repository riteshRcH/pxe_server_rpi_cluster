'''

    Module DocString: This file contains classes and functions that implement the PXE Server DHCP service
    
    struct used for conversions between Python values and C structs represented as Python strings
    
    
Character    Byte order                Size    Alignment
@            native                    native    native
=            native                    standard    none
<            little-endian            standard    none
>            big-endian                standard    none
!            network (= big-endian)    standard    none

Format    C Type        Python type            Standard size
x        pad byte                no value          
c        char                    string of length1 (1)     
b        signed char            integer (1)
B        unsigned char            integer (1)
?        _Bool                    bool (1)
h        short                    integer (2)
H        unsigned short            integer (2)
i        int                    integer (4)
I        unsigned int            integer (4)
l        long                    integer (4)
L        unsigned long            integer (4)
q        long long                integer (8)
Q        unsigned long long    integer (8)
f        float                    float (4)
d        double                    float (8)
s        char[]                    string          
p        char[]                    string          
P        void *                    integer

'''

import socket
import struct
import os
from collections import defaultdict
from time import time

class DHCPServerDaemon:
    '''
        Class Docstring: This class implements a DHCP Server, limited to pxe options,
        where the subnet /24 is hard coded. Implemented from RFC2131,
        RFC2132, https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
        and useHTTP://www.pix.net/software/pxeboot/archive/pxespec.pdf and TCP/IP protocol suite forouzan
        
        init stands for constructor
    '''
    def __init__(self, **dhcpServerSettings):
        
        self.ip = dhcpServerSettings.get('ip', '192.168.2.2')
        self.port = dhcpServerSettings.get('port', 67)
        self.offerFrom = dhcpServerSettings.get('offerFrom', '192.168.2.100')
        self.offerTo = dhcpServerSettings.get('offerTo', '192.168.2.150')
        self.subnetMask = dhcpServerSettings.get('subnetMask', '255.255.255.0')
        self.routerDefaultGateway = dhcpServerSettings.get('routerDefaultGateway', '192.168.2.1')
        self.dnsServer = dhcpServerSettings.get('dnsServer', '8.8.8.8')
        self.broadcast = dhcpServerSettings.get('broadcast', '<broadcast>')
        self.tftpServerIP = dhcpServerSettings.get('tftpServerIP', '192.168.2.2')
        self.netbootFilename = dhcpServerSettings.get('filename', 'pxelinux.0')
        self.useiPXE = dhcpServerSettings.get('useipxe', False)
        self.useHTTP = dhcpServerSettings.get('usehttp', False)
        self.enableDHCPProxyMode = dhcpServerSettings.get('enableDHCPProxyMode', False)     #ProxyDHCP mode
        self.enableVerboseOutput = dhcpServerSettings.get('enableVerboseOutput', False)     #verbose mode
        self.magic = struct.pack('!I', 0x63825363) #magic cookie

        if self.useHTTP and not self.useiPXE:
            print '\nWARNING: HTTP selected but iPXE disabled. Default PXE ROM i.e the firmware must support HTTP requests.\n'
        if self.useiPXE and self.useHTTP:
            self.netbootFilename = 'http://%s/%s' % (self.tftpServerIP, self.netbootFilename)
        if self.useiPXE and not self.useHTTP:
            self.netbootFilename = 'tftp://%s/%s' % (self.tftpServerIP, self.netbootFilename)

        if self.enableVerboseOutput:
            print 'INFO: DHCP server started in verbose/debug mode. DHCP server is using the following:'
            print '\tDHCP Server IP: ' + self.ip
            print '\tDHCP Server Port: ' + str (self.port)
            print '\tDHCP Lease Range: ' + self.offerFrom + ' - ' + self.offerTo
            print '\tDHCP Subnet Mask: ' + self.subnetMask
            print '\tDHCP Router: ' + self.routerDefaultGateway
            print '\tDHCP DNS Server: ' + self.dnsServer
            print '\tDHCP Broadcast Address: ' + self.broadcast
            print '\tDHCP File Server IP: ' + self.tftpServerIP
            print '\tDHCP File Name: ' + self.netbootFilename
            print '\tProxyDHCP Mode: ' + str(self.enableDHCPProxyMode)
            print '\tUsing iPXE: ' + str(self.useiPXE)
            print '\tUsing HTTP Server: ' + str(self.useHTTP)

        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            #Address family using as Internet with type UDP/Datagram 
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         #re use address as 1
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.serverSocket.bind(('', self.port ))                                        #bind to local machine i.e ''
        
        #key for the dictionary is MAC Address
        self.leases = defaultdict(lambda: {'ip': '', 'expire': 0, 'useiPXE': self.useiPXE})     #defaultdict adds key to dict if key not found with given defaults
        
    def listen(self):
        '''
            Method Docstring: Main listen loop at server for incoming DHCP packets
        '''
        while True:
            message, address = self.serverSocket.recvfrom(1024)
            clientmac = struct.unpack('!28x6s', message[:34])
            if self.enableVerboseOutput:
                print '[INFO] Received message'
                print '\t<--BEGIN MESSAGE-->\n\t' + repr(message) + '\n\t<--END MESSAGE-->'
            options = self.tlvParse(message[240:])
            if self.enableVerboseOutput:
                print '[INFO] Parsed received options'
                print '\t<--BEGIN OPTIONS-->\n\t' + repr(options) + '\n\t<--END OPTIONS-->'
            if not (60 in options and 'PXEClient' in options[60][0]) : continue
            type = ord(options[53][0]) #see RFC2131 page 10
            if type == 1:
                if self.enableVerboseOutput:
                    print '[INFO] Received DHCPOFFER'
                self.dhcpOffer(message)
            elif type == 3 and address[0] == '0.0.0.0' and not self.enableDHCPProxyMode:
                if self.enableVerboseOutput:
                    print '[INFO] Received DHCPACK'
                self.dhcpAck(message)
            elif type == 3 and address[0] != '0.0.0.0' and self.enableDHCPProxyMode:
                if self.enableVerboseOutput:
                    print '[INFO] Received DHCPACK'
                self.dhcpAck(message)
                
    def dhcpOffer(self, message):
        '''
            Method Docstring: This method responds to DHCP discovery with offer
        '''
        clientmac, headerResponse = self.craftHeader(message)
        optionsResponse = self.craftOptions(2, clientmac) #DHCPOFFER
        response = headerResponse + optionsResponse
        if self.enableVerboseOutput:
            print '[INFO] DHCPOFFER - Sending the following'
            print '\t<--BEGIN HEADER-->\n\t' + repr(headerResponse) + '\n\t<--END HEADER-->'
            print '\t<--BEGIN OPTIONS-->\n\t' + repr(optionsResponse) + '\n\t<--END OPTIONS-->'
            print '\t<--BEGIN RESPONSE-->\n\t' + repr(response) + '\n\t<--END RESPONSE-->'
        self.serverSocket.sendto(response, (self.broadcast, 68))
        
    def craftHeader(self, message):
        '''
            Method Docstring: This method crafts the DHCP header using parts of the message
        '''
        xid, flags, yiaddr, giaddr, chaddr = struct.unpack('!4x4s2x2s4x4s4x4s16s', message[:44])
        clientmac = chaddr[:6]
        
        #op, htype, hlen, hops, xid
        response =  struct.pack('!BBBB4s', 2, 1, 6, 0, xid)
        if not self.enableDHCPProxyMode:
            response += struct.pack('!HHI', 0, 0, 0) #secs, flags, ciaddr
        else:
            response += struct.pack('!HHI', 0, 0x8000, 0)
        if not self.enableDHCPProxyMode:
            if self.leases[clientmac]['ip']: #OFFER
                offer = self.leases[clientmac]['ip']
            else: #ACK
                offer = self.nextIP()
                self.leases[clientmac]['ip'] = offer
                self.leases[clientmac]['expire'] = time() + 86400
                if self.enableVerboseOutput:
                    print '[INFO] New DHCP Assignment - MAC: ' + self.printMAC(clientmac) + ' -> IP: ' + self.leases[clientmac]['ip']
            response += socket.inet_aton(offer) #yiaddr
        else:
            response += socket.inet_aton('0.0.0.0')
        response += socket.inet_aton(self.tftpServerIP) #siaddr
        response += socket.inet_aton('0.0.0.0') #giaddr
        response += chaddr #chaddr
        
        #bootp legacy pad
        response += chr(0) * 64 #server name
        if self.enableDHCPProxyMode:
            response += self.netbootFilename
            response += chr(0) * (128 - len(self.netbootFilename))
        else:
            response += chr(0) * 128
        response += self.magic #magic section
        return (clientmac, response)
    
    def craftOptions(self, opt53, clientmac):
        '''
            Method Docstring: This method crafts the DHCP option fields
                            opt53:
                                2 - DHCPOFFER
                                5 - DHCPACK
                            (See RFC2132 9.6)
        '''
        response = self.tlvEncode(53, chr(opt53)) #message type, offer
        response += self.tlvEncode(54, socket.inet_aton(self.ip)) #DHCP Server
        if not self.enableDHCPProxyMode:
            response += self.tlvEncode(1, socket.inet_aton(self.subnetMask)) #SubnetMask
            response += self.tlvEncode(3, socket.inet_aton(self.routerDefaultGateway)) #Router
            response += self.tlvEncode(51, struct.pack('!I', 86400)) #lease time
        
        #TFTP Server OR HTTP Server; if iPXE, need both
        response += self.tlvEncode(66, self.tftpServerIP)
        
        #netbootFilename null terminated
        if not self.useiPXE or not self.leases[clientmac]['useiPXE']:
            response += self.tlvEncode(67, self.netbootFilename + chr(0))
        else:
            response += self.tlvEncode(67, '/chainload.kpxe' + chr(0)) #chainload iPXE
            if opt53 == 5: #ACK
                self.leases[clientmac]['useiPXE'] = False
        if self.enableDHCPProxyMode:
            response += self.tlvEncode(60, 'PXEClient')
            response += struct.pack('!BBBBBBB4sB', 43, 10, 6, 1, 0b1000, 10, 4, chr(0) + 'PXE', 0xff)
        response += '\xff'
        return response

    def tlvEncode(self, tag, value):
        '''
            Method Docstring: Encode a TLV (Tag length value) option
        '''
        return struct.pack("BB", tag, len(value)) + value

    def tlvParse(self, raw):
        '''
            Method Docstring: Parse a string of TLV (Tag length value) encoded options.
        '''
        ret = {}
        while(raw):
            tag = struct.unpack('B', raw[0])[0]
            if tag == 0:  #padding
                raw = raw[1:]
                continue
            if tag == 255:  #end marker
                break
            length = struct.unpack('B', raw[1])[0]
            value = raw[2:2 + length]
            raw = raw[2 + length:]
            if tag in ret:
                ret[tag].append(value)
            else:
                ret[tag] = [value]
        return ret

    def printMAC(self, mac):
        '''
            Method Docstring: This method converts the MAC Address from binary to human-readable format of hex and colon separated chars for logging.
        '''
        return ':'.join(map(lambda x: hex(x)[2:].zfill(2), struct.unpack('BBBBBB', mac))).upper()
        
    def nextIP(self):
        '''
            Method Docstring: This method returns next unleased/unused IP from range;
                                also does lease expiry by overwrite.
        '''

        #if we use ints, we don't have to deal with octet overflow
        #or nested loops (up to 3 with 10/8); convert both to 32bit integers
        
        #e.g '192.168.1.1' to 3232235777
        encode = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]      #aton i.e address to number and vice versa
        
        #e.g 3232235777 to '192.168.1.1'
        decode = lambda x: socket.inet_ntoa(struct.pack('!I', x))           #! = network endianness
        
        fromhost = encode(self.offerFrom)
        tohost = encode(self.offerTo)
        
        #pull out already leased ips
        leased = [self.leases[i]['ip'] for i in self.leases
                if self.leases[i]['expire'] > time()]
        
        #convert to 32bit int
        leased = map(encode, leased)
        
        #loop through, make sure not already leased and not in form X.Y.Z.0
        for offset in xrange(tohost - fromhost):
            if (fromhost + offset) % 256 and fromhost + offset not in leased:
                return decode(fromhost + offset)

    def dhcpAck(self, message):
        '''
            Method Docstring: This method responds to DHCP request with acknowledge (DHCP_ACK)
        '''
        clientmac, headerResponse = self.craftHeader(message)
        optionsResponse = self.craftOptions(5, clientmac) #DHCPACK
        response = headerResponse + optionsResponse
        if self.enableVerboseOutput:
            print '[INFO] DHCPACK - Sending the following'
            print '\t<--BEGIN HEADER-->\n\t' + repr(headerResponse) + '\n\t<--END HEADER-->'
            print '\t<--BEGIN OPTIONS-->\n\t' + repr(optionsResponse) + '\n\t<--END OPTIONS-->'
            print '\t<--BEGIN RESPONSE-->\n\t' + repr(response) + '\n\t<--END RESPONSE-->'
        self.serverSocket.sendto(response, (self.broadcast, 68))
