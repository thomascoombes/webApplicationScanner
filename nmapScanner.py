import nmap
import socket

class Nmap:
    def __init__(self, target=None, port=None):
        self.target = target
        self.port = port





    def nmap_web_app(self):
        print("\nStarting Nmap scan on port", self.port)
                
        scanner = nmap.PortScanner()
        scanner.scan(self.target, self.port, '-sV -sS -sC')
        print("Target Status:", scanner[self.target].state())
        print(scanner.scan(info))
       


	


if __name__ == "__main__":
    main()







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
