import requests
import re

from activeScanRules.activeScanner import ActiveScanner


class ScanSQLInject(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        return "payloads/sqlInjectionPayloads/detect/MySQL/MySQL.txt"

    def initialise_error_messages(self):
        error_messages = []

        return error_messages

    def test_payloads(self, target_url, form_fields):
        if form_fields:
            self.test_payloads_in_forms(target_url, form_fields)

        url_params = self.extract_url_params(target_url)
        base_url = self.get_base_url(target_url)
        if url_params and base_url not in self.visited_base_urls:
            self.test_payloads_in_url(target_url, url_params)
            self.visited_base_urls.add(base_url)  # Mark the base URL as visited to prevent redundant testing

    def test_payloads_in_url(self, target_url, url_params):
        # Open the file containing SQL payloads
        with open(self.initialise_payloads(), "r") as payload_file:
            # Initialise a flag to track if any potential vulnerability is found
            potential_vulnerability_found = False
            for payload in payload_file:
                self.logger.info(f"\tTesting payload: {payload} on {target_url}")
                try:
                    # Construct the URL with the payload
                    modified_url = self.construct_modified_url(target_url, url_params, payload)
                    self.logger.info(f"\tModified URL: {modified_url}")
                    # Send HTTP request to the modified URL
                    response = requests.get(modified_url)
                    # Call check response method to detect potential vulnerabilities
                    if self.check_response(response, payload, target_url):
                        potential_vulnerability_found = True
                        break  # Break out of the loop if vulnerability found
                except Exception as e:
                    self.logger.info(f"\tAn error occurred while testing SQL injection in URL parameter: {e}")
            # After testing all payloads, if no potential vulnerability is found, print the message
            if not potential_vulnerability_found:
                self.logger.info(f"\tNo SQL injection URL parameter vulnerability found in URL parameters at: {target_url}")

    def test_payloads_in_forms(self, target_url, form_fields):
        # Open the file containing SQL payloads
        with open(self.initialise_payloads(), "r") as payload_file:
            # Initialise a flag to track if any potential vulnerability is found
            potential_vulnerability_found = False
            for payload in payload_file:
                self.logger.info(f"\tTesting payload: {payload} on {target_url}")
                # Prepare form data with SQL payload
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

                    if self.check_response(response, payload, target_url):
                        potential_vulnerability_found = True
                        break  # Break out of the loop if vulnerability found

                except Exception as e:
                    self.logger.error(f"\tAn error occurred while sending form with SQL payload to {target_url}: {e}")

            # After testing all payloads, if no potential vulnerability is found, print the message
            if not potential_vulnerability_found:
                self.logger.info(f"\tNo SQL injection form vulnerability found at: {target_url}")

    def check_response(self, response, payload, url):
        # Check if response indicates successful injection
        if response.status_code == 200:
            # Check if the response contains common SQL error messages or patterns
            if (re.search(r'(error|syntax|exception|warning)', response.text, re.IGNORECASE) and
                    re.search(r'(SQL|mysql_fetch_array|mysqli_fetch_array)', response.text) and
                    payload in response.text):
                self.logger.warning(
                    f"\tPotential SQL injection vulnerability found at: {url} with payload {payload}")
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")

