import requests

from activeScanRules.activeScanner import ActiveScanner

class ScanVerbTampering(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)


    def initialise_payloads(self):
        payloads = ['GET', 'POST', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD']
        return payloads

    def start_scan(self):
        # Open the file containing target URLs
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        with open(self.targets_file, "r") as file:
            for target_url in file:
                target_url = target_url.strip()  # Remove whitespace characters
                self.test_payloads(target_url)

    def test_payloads(self, target_url):
        potential_vulnerability_found = False
        original_response = self.send_request(target_url, method='GET')
        for payload in self.initialise_payloads():
            # Skip the original HTTP method used
            if payload == 'GET':
                continue

            tampered_response = self.send_request(target_url, method=payload)

            if self.check_response(tampered_response, original_response):
                self.logger.warning(
                    f"\tPotential verb tampering vulnerability found at: {target_url} with method {payload}")
                print(f"\033[31m[+] Potential verb tampering vulnerability found at: {target_url} with method {payload}\033[0m")
                potential_vulnerability_found = True
                break  # Exit the loop if potential vulnerability is found
        if not potential_vulnerability_found:
            self.logger.info(f"No verb tampering vulnerability found at: {target_url}")
            print(f"\033[32m[+] No verb tampering vulnerability found at: {target_url}\033[0m")

    def send_request(self, target_url, method):
        try:
            response = requests.request(method, target_url)
            return response
        except Exception as e:
            self.logger.error(f"\tAn error occurred while sending request to {target_url} with method {method}: {e}")

    def check_response(self, tampered_response, original_response):
        #if tampered_response.status_code == 200:
        if tampered_response.text == original_response.text:
            return True

