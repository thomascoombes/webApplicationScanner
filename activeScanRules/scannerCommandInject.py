import requests
import re

from activeScanRules.activeScanner import ActiveScanner

class ScanCommandInject(ActiveScanner):
    def __init__(self, host_os=None, visited_urls=None, log_file=None):
        self.host_os = host_os
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        if self.host_os == "unix":
            return "payloads/commandInjectionPayloads/unixPayloads.txt"
        elif self.host_os == "windows":
            return "payloads/commandInjectionPayloads/windowsPayloads.txt"
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return "payloads/commandInjectionPayloads/unix_payloads.txt"

    def test_payloads(self, target_url, form_fields):
        # Open the file containing command injection payloads
        with open(self.initialise_payloads(), "r") as payload_file:
            # Initialise a flag to track if any potential vulnerability is found
            potential_vulnerability_found = False
            for payload in payload_file:
                self.logger.info(f"\tTesting payload: {payload} on {target_url}")
                # Prepare form data with command injection payload
                form_data = {}
                for field_name, _ in form_fields:
                    form_data[field_name] = payload
                try:
                    # Get the form method (post or get)
                    form_method = form_data.get('method', 'post').lower()
                    # Get the action URL or set it to the target URL if not found
                    action = form_data.get('action', target_url)
                    # Extract input fields from the form_data
                    inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                    # Prepare post data for submission
                    post_data = {}
                    for input_name in inputs:
                        post_data[input_name] = form_data[input_name]
                    # Check if method is post or get
                    if form_method == 'post':
                        response = requests.post(action, data=post_data)
                    else:
                        response = requests.get(action, params=post_data)

                    # Call check response method to detect potential vulnerabilities
                    if self.check_response(response, payload, target_url):
                        potential_vulnerability_found = True
                        break  # Break out of the loop if vulnerability found
                except Exception as e:
                    self.logger.error(
                        f"\tAn error occurred while sending form with command injection payload to {target_url}: {e}")

            # After testing all payloads, if no potential vulnerability is found, print the message
            if not potential_vulnerability_found:
                self.logger.info(f"\tNo command injection form vulnerability found at: {target_url}")

    def check_response(self, response, payload, url):
        # Check if response indicates successful injection
        if response.status_code == 200:
            # Check if the response contains common command injection error messages or patterns
            if re.search(r'(uid|gid|groups)', response.text, re.IGNORECASE):
                self.logger.warning(
                    f"\tPotential command injection vulnerability found at: {url} with payload {payload} ")
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")
        return False