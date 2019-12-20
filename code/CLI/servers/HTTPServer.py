'''

This file contains classes and functions that implement the PXE Server HTTP service

'''

import socket
import struct
import os

class HTTPD:
    '''
        This class implements a HTTP Server, limited to GET and HEAD,
        from RFC2616, RFC7230
    '''
    def __init__(self, **serverSettings):
        
        self.ip = serverSettings.get('ip', '0.0.0.0')
        self.port = serverSettings.get('port', 80)
        self.netbootDirectory = serverSettings.get('netbootDirectory', '.')
        self.enableVerboseOutput = serverSettings.get('enableVerboseOutput', False) #debug mode
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind((self.ip, self.port))
        self.serverSocket.listen(1)

        # Start in network boot file directory and then chroot, 
        # this simplifies target later as well as offers a slight security increase
        os.chdir (self.netbootDirectory)
        os.chroot ('.')

        if self.enableVerboseOutput:
            print 'NOTICE: HTTP server started in debug mode. HTTP server is using the following:'
            print '\tHTTP Server IP: ' + self.ip
            print '\tHTTP Server Port: ' + str(self.port)
            print '\tHTTP Network Boot Directory: ' + self.netbootDirectory

    def handleRequest(self, connection, addr):
        '''This method handles HTTP request'''
        request = connection.recv(1024)
        if self.enableVerboseOutput:
            print '[DEBUG] HTTP Recieved message from ' + repr(addr)
            print '\t<--BEGIN MESSAGE-->\n\t' + repr(request) + '\n\t<--END MESSAGE-->'
        startline = request.split('\r\n')[0].split(' ')
        method = startline[0]
        target = startline[1]
        if not os.path.lexists(target) or not os.path.isfile(target):
            status = '404 Not Found'
        elif method not in ('GET', 'HEAD'):
            status = '501 Not Implemented'
        else:
            status = '200 OK'
        response = 'HTTP/1.1 %s\r\n' % status
        if status[:3] in ('404', '501'): #fail out
            connection.send(response)
            connection.close()
            if self.enableVerboseOutput:
                print '[DEBUG] HTTP Sending message to ' + repr(addr)
                print '\t<--BEING MESSAGE-->\n\t' + repr(response) + '\n\t<--END MESSAGE-->'
            return
        response += 'Content-Length: %d\r\n' % os.path.getsize(target)
        response += '\r\n'
        if method == 'HEAD':
            connection.send(response)
            connection.close()
            if self.enableVerboseOutput:
                print '[DEBUG] HTTP Sending message to ' + repr(addr)
                print '\t<--BEING MESSAGE-->\n\t' + repr(response) + '\n\t<--END MESSAGE-->'
            return
        handle = open(target)
        response += handle.read()
        handle.close()
        connection.send(response)
        connection.close()
        if self.enableVerboseOutput:
            print '[DEBUG] HTTP Sending message to ' + repr(addr)
            print '\t<--BEING MESSAGE-->\n\t' + repr(response) + '\n\t<--END MESSAGE-->'
            print '\tHTTP File Sent - http://%s -> %s:%d' % (target, addr[0], addr[1])

    def listen(self):
        '''This method is the main loop that listens for requests'''
        while True:
            conn, addr = self.serverSocket.accept()
            self.handleRequest(conn, addr)
