# Portable Computing Environment Using Raspberry Pi Cluster (Python PXE Server) 2015

A number of Raspberry Pi's were "known" to each over LAN with 1 of them hosting a PXE (Preboot eXecution Environment) server (includes local HTTP server, local TFTP server, local DHCP server OR the ability to forward DHCP DORA (Discover, Offer, Request, Acknowledge) packets to proxy DHCP server such as a WiFi router).

PXE is a protocol & standard (now incorported into UEFI (Unified Extensible Firmware Interface)) by Intel which specifies way for network booting a PC (with disk or diskless) off an iso hosted on some other host. Whenever a computer boots up, there is a CPU RESET event and then the control gets transferred to the BIOS/UEFI which performs POST (Power on Self-Test) and then it looks for a bootloader in the defined boot sequence (hard disk/partition/usb-drive order). Usually the computer boots up from the hard drive or USB by executing the bootloader which in turn loads the kernel into RAM followed by other OS files; this project instead aims to boot a computer after acquiring file(s) via the Network Interface Card (NIC) using PXE protocol to create a portable computing environment by loading the whole OS into RAM. This project acquires the necessary files to boot either using HTTP over LAN/Internet or via TFTP.

Local HTTP, DHCP & TFTP are coded purely/fully in python.

## PXE Server CLI (Command Line Interface)

![CLI1](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/CLI1.png)

![CLI2](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/CLI2.png)

## PXE Server GUI (Graphical User Interface) using python-tk (tkinter) package

![GUI1](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI1.png)

![GUI2](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI2.png)

![GUI3](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI3.png)

![GUI4](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI4.png)

![GUI5](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI5.png)

![GUI6](https://raw.githubusercontent.com/riteshRcH/pxe_server_rpi_cluster/master/screenshots/GUI6.png)
