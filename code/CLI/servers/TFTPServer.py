'''

    Module Docstring: This file contains classes and functions that implement the PXE Server TFTP service

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

class TFTPServerDaemon:
    '''
        Class Docstring: This class implements a read-only TFTP server implemented from RFC1350 and RFC2348
    '''
    def __init__(self, **TFTPServerSettings):
        self.ip = TFTPServerSettings.get('ip', '0.0.0.0')           #bind to local machine on which py script is run
        self.port = TFTPServerSettings.get('port', 69)
        self.netbootDirectory = TFTPServerSettings.get('netbootDirectory', '.')
        self.enableVerboseOutput = TFTPServerSettings.get('enableVerboseOutput', False) #verbose mode
        
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind((self.ip, self.port))

        if self.enableVerboseOutput:
            print 'INFO: TFTP server started in verbose/debug mode. TFTP server is using the following settings:'
            print '\tTFTP Server IP: ' + self.ip
            print '\tTFTP Server Port: ' + str(self.port)
            print '\tTFTP Network Boot Directory: ' + self.netbootDirectory

        #key for the dictionary is (address, port) pair
        self.ongoing = defaultdict(lambda: {'netbootFilename': '', 'handle': None, 'block': 1, 'blksize': 512})

        # Start in network boot file directory and then chroot for the current py process (PVM), 
        # this simplifies target later as well as offers a slight security increase
        os.chdir (self.netbootDirectory)
        os.chroot ('.')                     #MAKES IT LINUX/POSIX DEPENDENT
        
    def listen(self):
        '''This method listens for incoming requests'''
        while True:
            message, address = self.serverSocket.recvfrom(1024)
            opcode = struct.unpack('!H', message[:2])[0]
            if opcode == 1: #read the request
                if self.enableVerboseOutput:
                    print '[INFO] TFTP receiving request'
                self.read(address, message)
            if opcode == 4:
                 if self.ongoing.has_key(address):
                    self.sendDataBlock(address)

    def netbootFilename(self, message):
        '''
            Method Docstring: The first null-delimited field after the OPCODE 
                                is the netbootFilename. This method returns the netbootFilename
                                from the message.
        '''
        return message[2:].split(chr(0))[0]

    def sendFileNotFoundResponse(self, address):
        '''
            Method Docstring: 
                short int 5 -> Error
                short int 1 -> File Not Found

                This method sends the message to the client
        '''
        response =  struct.pack('!H', 5) #error code
        response += struct.pack('!H', 1) #file not found
        response += 'File Not Found'
        if self.enableVerboseOutput:
            print "[INFO] TFTP Sending 'File Not Found'"
        self.serverSocket.sendto(response, address)

    def sendDataBlock(self, address):
        '''
            short int 3 -> Data Block
        '''
        descriptor = self.ongoing[address]
        response =  struct.pack('!H', 3) #opcode 3 is DATA, also sent block number
        response += struct.pack('!H', descriptor['block'] % 2 ** 16)
        data = descriptor['handle'].read(descriptor['blksize'])
        response += data
        self.serverSocket.sendto(response, address)
        if len(data) != descriptor['blksize']:
            descriptor['handle'].close()
            if self.enableVerboseOutput:
                print '[INFO] TFTP File Sent - tftp://%s -> %s:%d' % (descriptor['netbootFilename'], address[0], address[1])
            self.ongoing.pop(address)
        else:
            if self.enableVerboseOutput:
                print '[INFO] TFTP Sending block ' + repr(descriptor['block'])
            descriptor['block'] += 1

    def read(self, address, message):
        '''
            On RRQ OPCODE:
                file exists -> reply with file
                file does not exist -> reply with error
        '''
        filename = self.netbootFilename(message)
        if not os.path.lexists(filename):
            self.sendFileNotFoundResponse(address)
            return
        self.ongoing[address]['netbootFilename'] = filename
        self.ongoing[address]['handle'] = open(filename, 'r')
        options = message.split(chr(0))[3: -1]
        options = dict(zip(options[0::2], options[1::2]))
        response = ''
        if 'blksize' in options:
            response += 'blksize' + chr(0)
            response += options['blksize']
            response += chr(0)
            self.ongoing[address]['blksize'] = int(options['blksize'])
        filesize = os.path.getsize(self.ongoing[address]['netbootFilename'])
        if filesize > (2**16 * self.ongoing[address]['blksize']):
            print '\nWARNING: TFTP request too big, attempting transfer anyway.\n'
            print '\tDetails: Filesize %s is too big for blksize %s.\n' % (filesize, self.ongoing[address]['blksize'])
        if 'tsize' in options:
            response += 'tsize' + chr(0)
            response += str(filesize)
            response += chr(0)
        if response:
            response = struct.pack('!H', 6) + response
            self.serverSocket.sendto(response, address)
        self.sendDataBlock(address)