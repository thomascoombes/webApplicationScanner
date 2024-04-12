import requests

from activeScanRules.activeScanner import ActiveScanner

class ScanVerbTampering(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)


    def initialise_payloads(self):
        payloads = ['GET', 'POST', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD']
        return payloads

    def test_payloads(self, target_url, form_fields):
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
                potential_vulnerability_found = True
                break  # Exit the loop if potential vulnerability is found
        if not potential_vulnerability_found:
            self.logger.info(f"\tNo verb tampering vulnerability found at: {target_url}")

    def send_request(self, target_url, method):
        try:
            response = requests.request(method, target_url)
            return response.text
        except Exception as e:
            self.logger.error(f"\tAn error occurred while sending request to {target_url} with method {method}: {e}")

    def check_response(self, tampered_response, original_response):
        if tampered_response == original_response:
            return True