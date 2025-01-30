import os
import platform

#function used to clear screen in cmd when the u chose the user chose option and start the scan
def cleanScreen():
    system = platform.system()
    if str(system) == "windows" or "win":
        os.system("cls")
    else:
        os.system("clear") 
#get port name from port number
def GetPortName(port):
    PortList = {
            "20": "FTP",
            "21": "FTP",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "67": "DHCP Server",
            "68": "DHCP Client",
            "69": "TFTP",
            "80": "HTTP",
            "110": "POP3",
            "123": "NTP",
            "135": "RPC",
            "137": "NetBIOS",
            "138": "NetBIOS",
            "139": "NetBIOS",
            "143": "IMAP",
            "161": "SNMP",
            "194": "IRC",
            "443": "HTTPS",
            "445": "SMB",
            "465": "SMTPS",
            "514": "Syslog",
            "993": "IMAPS",
            "995": "POP3S",
            "1080": "SOCKS",
            "1433": "MSSQL",
            "1521": "Oracle DB",
            "3306": "MySQL",
            "3389": "RDP",
            "5432": "PostgreSQL",
            "5900": "VNC",
            "8080": "HTTP Proxy",
            "8443": "HTTPS Alternate",
        }
    if PortList.get(port) != None:
        return PortList.get(port)
    else:
        return "Unknown port number"
#banner when script tool start
def PrintBanner():
    print('''
╔╗╔┌─┐┌┬┐┬ ┬┌─┐┬─┐┬┌─  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
║║║├┤  │ ││││ │├┬┘├┴┐  ╚═╗│  ├─┤││││││├┤ ├┬┘
╝╚╝└─┘ ┴ └┴┘└─┘┴└─┴ ┴  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─''')
    


