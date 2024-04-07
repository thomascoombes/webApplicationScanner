import requests
import re
from activeScanRules.activeScanner import ActiveScanner

class ScanCommandInject(ActiveScanner):
    def __init__(self, host_os=None, visited_urls="output/testURLs.txt", potential_vulnerability_file=None):
        self.potential_vulnerability_file = potential_vulnerability_file
        super().__init__(visited_urls, self.potential_vulnerability_file)
        self.host_os = host_os

    def initialise_payloads(self):
        if self.host_os == "unix":
            return "payloads/commandInjectionPayloads/unixPayloads.txt"
        elif self.host_os == "windows":
            return "payloads/commandInjectionPayloads/windowsPayloads.txt"
        else:
            print("Invalid or unspecified host operating system. Defaulting to Unix payloads.")
            return "payloads/commandInjectionPayloads/unix_payloads.txt"

    def send_form_with_payloads(self, target_url, form_fields, payload_file):
        # Open the file containing command injection payloads
        with open(payload_file, "r") as payload_file:
            # Initialise a flag to track if any potential vulnerability is found
            potential_vulnerability_found = False
            for payload in payload_file:
                print(f"Testing payload: {payload} on {target_url}")
                # Prepare form data with command injection payload
                form_data = {}
                for field_name, _ in form_fields:
                    form_data[field_name] = payload
                try:
                    # Send POST request with form data
                    response = requests.post(target_url, data=form_data)
                    # Check if response indicates successful injection
                    if response.status_code == 200:
                        # Check if the response contains common command injection error messages or patterns
                        if re.search(r'(uid)', response.text, re.IGNORECASE) and re.search(r'(gid)', response.text) and re.search(r'(groups)', response.text):
                            print(
                                f"Potential command injection vulnerability found at: {target_url} with payload {payload} \n")
                            self.record_potential_vulnerability(target_url)
                            # Set the flag to indicate potential vulnerability found
                            potential_vulnerability_found = True
                            break
                    else:
                        print(f"Unexpected response code ({response.status_code}) for {target_url}")
                except Exception as e:
                    print(f"An error occurred while sending form with command injection payload to {target_url}: {e}")

            # After testing all payloads, if no potential vulnerability is found, print the message
            if not potential_vulnerability_found:
                print(f"No command injection vulnerability found at: {target_url}\n")

    def record_potential_vulnerability(self, target_url):
        # Write potential vulnerability to file
        with open(self.potential_vulnerability_file, "a") as file:
            file.write(target_url + "\n")