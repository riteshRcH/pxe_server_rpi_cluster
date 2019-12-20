# Portable Computing Environment Using Raspberry Pi Cluster (Python)

A number of Raspberry Pi's were "known" to each over LAN with 1 of them hosting a PXE server (includes local HTTP server, local TFTP server, local DHCP server OR the ability to forward DHCP DORA (Discover, Offer, Request, Acknowledge) packets to proxy DHCP server such as a WiFi router)

Local HTTP, DHCP & TFTP are coded purely/fully in python.

The PXE server can be configured using 2 interfaces

* CLI (Command Line Interface)
* GUI (Graphicsla User Interface) using python-tk (tkinter) package
