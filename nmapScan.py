import nmap
import sys

from cti.nvdInterface import NvdIntelligence

class NmapScanner:
    def __init__(self, api_key=None, target=None, port=None, aggression_level=None, log_file=None):
        self.port = port
        self.aggression_level = aggression_level
        self.target = target
        self.log_file = log_file
        self.api_key = api_key
        self.nvd = NvdIntelligence(self.api_key)

    def nmap_web_app(self):
        try:
            nm = nmap.PortScanner()

            with open(self.log_file, 'w') as file:
                file.write(f"Nmap Version: {nm.nmap_version()}\n")
                print(f"\033[36mNmap Version: {nm.nmap_version()}")

                print("Starting Nmap scan")

                aggression_flag = f"-T{self.aggression_level - 1}" if self.aggression_level in range(1, 7) else "-T5"

                if self.aggression_level == 5 or self.aggression_level == 6:
                    aggression_flag = aggression_flag + " -O -A"
                    file.write("Aggression level 4 or 5 detected. Enabling aggressive scan (-O -A).\n")
                    print("Aggression level 4 or 5 detected. Enabling aggressive scan (-O -A).")

                nmap_command = f"nmap {self.target} -p {self.port} -v -sV -sC {aggression_flag}"
                file.write("Nmap Command: " + nmap_command + "\n")
                print(f"Nmap Command: {nmap_command}\n")
                result = nm.scan(nmap_command)
                #print(result)
                file.write("Nmap Scan results:\n")
                for host, scan_result in result['scan'].items():
                    print("Host:", host)
                    file.write("Host: " + host + "\n")
                    for port, port_data in scan_result['tcp'].items():
                        print(f"Port {port}:", port_data['state'], "-", port_data['name'], "-",
                              port_data.get('product', ''), port_data.get('version', ''))
                        file.write(
                            f"Port {port}: {port_data['state']} - {port_data['name']} - {port_data.get('product', '')} {port_data.get('version', '')}\n")
                        if port_data.get('script') and 'http-title' in port_data['script']:
                            print("HTTP Title:", port_data['script']['http-title'])
                            file.write("HTTP Title: " + port_data['script']['http-title'] + "\n")

                        if port_data.get('script') and 'http-server-header' in port_data['script']:
                            print("HTTP Title:", port_data['script']['http-server-header'])
                            file.write("http-server-header: " + port_data['script']['http-server-header'] + "\n")

                        if 'product' in port_data and 'version' in port_data:
                            print("Product:", port_data['product'])
                            file.write("Product: " + port_data['product'] + "\n")
                            print("Version:", port_data['version'])
                            file.write("Version: " + port_data['version'] + "\n")

                        if 'extrainfo' in port_data:
                            print("Extra Info:", port_data['extrainfo'])
                            file.write("Extra Info: " + port_data['extrainfo'] + "\n")

                        if 'cpe' in port_data:
                            cpe = port_data['cpe']
                            print(cpe)
                            #cpes = self.nvd.search_cpe(cpe)

        except Exception as e:
            print(f"\033[31mCannot scan {self.target} on port {self.port}: {e}\033[0m")
            sys.exit()