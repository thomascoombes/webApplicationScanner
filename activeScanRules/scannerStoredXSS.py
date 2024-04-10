import requests
import re
import logging
from activeScanRules.activeScanner import ActiveScanner

class ScanStoredXSS(ActiveScanner):
    def __init__(self, visited_urls="output/testURLs.txt", log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        return "payloads/xssPayloads/xss-payload-list-small.txt"

    def send_payload(self, target_url, payload):
        try:
            response = requests.post(target_url, data={'user_input': payload})
            if response.status_code == 200:
                self.logger.info(f"Payload '{payload}' stored successfully at {target_url}")
                return True
            else:
                self.logger.error(f"Failed to store payload '{payload}' at {target_url}. Status code: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"An error occurred while simulating stored XSS at {target_url}: {e}")
            return False

    def test_stored_xss(self, target_url):
        with open(self.initialise_payloads(), "r") as payload_file:
            for payload in payload_file:
                payload = payload.strip()
                self.logger.setLevel(logging.INFO)
                self.logger.info(f"Testing stored XSS with payload: {payload} on {target_url}")
                if self.send_payload(target_url, payload):
                    stored_data = self.retrieve_stored_data(target_url)
                    if self.check_reflections(stored_data, payload):
                        self.logger.warning(f"Potential Stored XSS vulnerability found at: {target_url} with payload: {payload}")
                        break

    def retrieve_stored_data(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                self.logger.error(f"Failed to retrieve stored data from {target_url}. Status code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"An error occurred while retrieving stored data from {target_url}: {e}")
            return None

    def check_reflections(self, response_text, payload):
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            return True
        return False
        # this function will probably call other functions in order to test the reflections

