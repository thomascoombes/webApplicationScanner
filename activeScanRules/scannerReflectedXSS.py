import requests
import re
import logging
from activeScanRules.activeScanner import ActiveScanner


class ScanReflectedXSS(ActiveScanner):
    def __init__(self, visited_urls="output/testURLs.txt", potential_vulnerability_file=None):
        super().__init__(visited_urls, potential_vulnerability_file)
        self.logger = logging.getLogger(__name__)

    def initialise_payloads(self):
        return "payloads/xssPayloads/xss-payload-list-small.txt"

    def test_payloads(self, target_url, form_fields, payload_file_path):
        with open(payload_file_path, "r") as payload_file:
            for payload in payload_file:
                payload = payload.strip()
                self.logger.info(f"Testing payload: {payload} on {target_url}")
                form_data = {}
                for field_name, _ in form_fields:
                    form_data[field_name] = payload

                try:
                    form_method = form_data.get('method', 'post').lower()
                    action = form_data.get('action', target_url)
                    inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                    post_data = {}
                    for input_name in inputs:
                        post_data[input_name] = form_data[input_name]

                    if form_method == 'post':
                        response = requests.post(action, data=post_data)
                    else:
                        response = requests.get(action, params=post_data)

                    if response.status_code == 200:
                        if (self.check_content_length(response) or
                                self.is_reflected_xss(response.text, payload)):
                            vulnerability_reason = ""
                            if self.check_content_length(response):
                                vulnerability_reason = "Content length exceeded threshold"
                            print("\n")
                            self.logger.warning(
                                f"Potential XSS vulnerability found at: {target_url} with payload {payload}. Reason: {vulnerability_reason}")
                            print("\n\n")
                            self.record_potential_vulnerability(target_url, payload)
                            break
                    else:
                        self.logger.error(f"Unexpected response code ({response.status_code}) for {target_url}")
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"An error occurred while sending form with XSS payload to {target_url}: {e}")
                except Exception as e:
                    self.logger.exception(f"An unexpected error occurred: {e}")
            else:
                print("\n")
                self.logger.info(f"No XSS vulnerability found at: {target_url}")
                print("\n\n")

    def check_content_length(self, response, threshold=10):
        original_length = len(response.text)
        response_with_injection_length = len(response.content)
        return response_with_injection_length > original_length + threshold

    def record_potential_vulnerability(self, target_url, payload):
        with open(self.potential_vulnerability_file, "a") as file:
            file.write(f"{target_url} - Payload: {payload}\n")

    def is_reflected_xss(self, response_text, payload):
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            return True
        return False