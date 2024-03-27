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

            # print("Target Status:", nm[self.target].state())

            result = nm.scan(self.target, str(self.port), '-v -sV -sC', 'tcp')

            # print(result)
            port_status = (result['scan'][self.target]['tcp'][self.port]['state'])
            print(f"Port {self.port} is {port_status}")

        except Exception as e:
            print(f"Cannot scan {self.target} on port {self.port}: {e}")
            sys.exit()