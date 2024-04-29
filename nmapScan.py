import nmap
import sys
import logging

class NmapScanner:
    def __init__(self, target=None, port=None, aggression_level=None, log_file=None):
        self.port = port
        self.aggression_level = aggression_level
        self.target = target
        self.log_file = log_file
        #logging.basicConfig(filename=self.log_file, level=logging.INFO,
        #                    format='%(levelname)s - %(message)s')

    def nmap_web_app(self):
        print(self.log_file)
        try:
            nm = nmap.PortScanner()

            print(f"\033[36mNmap Version: {nm.nmap_version()}")
            logging.info(f"Nmap Version: {nm.nmap_version()}")
            print("Starting Nmap scan")

            # Mapping aggression level to -T flag (0-5)
            aggression_flag = f"-T{self.aggression_level - 1}" if self.aggression_level in range(1, 7) else "-T5"

            # Adding -O and -A flags for aggression levels 4 and 5
            if self.aggression_level == 5 or self.aggression_level == 6:
                aggression_flag = aggression_flag + " -O -A"
                print("Aggression level 4 or 5 detected. Enabling aggressive scan (-O -A).")

            nmap_command = f"nmap {self.target} -p {self.port} -v -sV -sC {aggression_flag}"
            # --version-intensity

            print("Nmap Command:", nmap_command)
            logging.info("Nmap Command: %s", nmap_command)
            result = nm.scan(nmap_command)
            print("Nmap Scan results:")
            for host, scan_result in result['scan'].items():
                print("Host:", host)
                logging.info("Host: %s", host)
                if 'hostnames' in scan_result:
                    print("Hostnames:", ', '.join([hostname['name'] for hostname in scan_result['hostnames']]))
                    logging.info("Hostnames: %s",
                                 ', '.join([hostname['name'] for hostname in scan_result['hostnames']]))
                for port, port_data in scan_result['tcp'].items():
                    print(f"Port {port}:", port_data['state'], "-", port_data['name'], "-",
                          port_data.get('product', ''), port_data.get('version', ''))
                    logging.info("Port %s: %s - %s - %s %s", port, port_data['state'], port_data['name'],
                                 port_data.get('product', ''), port_data.get('version', ''))
                    if 'http-title' in port_data:
                        print("HTTP Title:", port_data['http-title'])
                        logging.info("HTTP Title: %s", port_data['http-title'])

        except Exception as e:
            print(f"Cannot scan {self.target} on port {self.port}: {e}")
            sys.exit()


