import requests
import re
import logging
from activeScanRules.activeScanner import ActiveScanner


class ScanReflectedXSS(ActiveScanner):
    def __init__(self, visited_urls="output/testURLs.txt", log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        return "payloads/xssPayloads/xss-payload-list-small.txt"

    def test_payloads(self, target_url, form_fields):
        with open(self.initialise_payloads(), "r") as payload_file:
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
                                self.check_reflections(response.text, payload)):
                            vulnerability_reason = ""
                            if self.check_content_length(response):
                                vulnerability_reason = "Content length exceeded threshold"
                            self.logger.warning(
                                f"Potential XSS vulnerability found at: {target_url} "
                                f"with payload {payload}. Reason: {vulnerability_reason}")
                            break
                    else:
                        self.logger.error(f"Unexpected response code ({response.status_code}) for {target_url}")
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"An error occurred while sending form with XSS payload to {target_url}: {e}")
                except Exception as e:
                    self.logger.exception(f"An unexpected error occurred: {e}")
            else:
                self.logger.info(f"No XSS vulnerability found at: {target_url}")

    def check_content_length(self, response, threshold=10):
        original_length = len(response.text)
        response_with_injection_length = len(response.content)
        return response_with_injection_length > original_length + threshold

    def check_reflections(self, response_text, payload):
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            return True
        return False
