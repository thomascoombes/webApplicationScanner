import nmap
import socket
import sys


class Nmap:
    def __init__(self, target=None, port=None):
        self.target = target
        self.port = port

    def nmap_web_app(self):

        try:
            nm = nmap.PortScanner()

            print("\nNmap Version:", nm.nmap_version())
            print("Starting Nmap scan on port", self.port)

            #print("Target Status:", nm[self.target].state())
            
            result = nm.scan(self.target,str(self.port),'-v -sV -sC','tcp')
            
            #print(result)
            port_status = (result['scan'][self.target]['tcp'][self.port]['state'])
            print(f"Port {self.port} is {port_status}")


        except:
            print(f"Cannot scan {self.target} on port {self.port}.")
            sys.exit()



#scanner.scan(ip_addr,"1-1024",resp_dict[resp][0])


























"""def convert_url(self):
	    ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            )
        
        if not re.match(ip_pattern, self.target):
            ip = socket.gethostbyname(self.target)
	    
        else:
	    ip = self.target
"""
