import nmap
import sys


class NmapScanner:
    def __init__(self, target=None, port=None, aggression_level=None, version_intensity=None):
        self.port = port
        self.aggression_level = aggression_level
        self.version_intensity = version_intensity
        self.target = target

    def nmap_web_app(self):
        try:
            nm = nmap.PortScanner()

            print("\nNmap Version:", nm.nmap_version())
            print("Starting Nmap scan")

            # Mapping aggression level to -T flag (0-5)
            aggression_flag = f"-T{self.aggression_level - 1}" if self.aggression_level in range(1, 7) else "-T5"

            # Mapping version intensity to appropriate value (0-9)
            version_intensity = self.map_version_intensity(self.version_intensity)

            result = nm.scan(self.target, str(self.port),
                             f'-v -sV -sC --version-intensity {version_intensity} {aggression_flag}')

            print("\nScan results:")
            for host, scan_result in result['scan'].items():
                print("Host:", host)
                if 'hostnames' in scan_result:
                    print("Hostnames:", ', '.join([hostname['name'] for hostname in scan_result['hostnames']]))
                for port, port_data in scan_result['tcp'].items():
                    print(f"Port {port}:", port_data['state'], "-", port_data['name'], "-",
                          port_data.get('product', ''), port_data.get('version', ''))
                    if 'http-title' in port_data:
                        print("HTTP Title:", port_data['http-title'])

        except Exception as e:
            print(f"Cannot scan {self.target} on port {self.port}: {e}")
            sys.exit()

    def map_version_intensity(self, intensity):
        if intensity == 1:
            return "0,1"
        elif intensity == 2:
            return "2,3"
        elif intensity == 3:
            return "4"
        elif intensity == 4:
            return "5,6"
        elif intensity == 5:
            return "7,8"
        elif intensity == 6:
            return "9"
        else:
            return "9"  # Default to the highest intensity
