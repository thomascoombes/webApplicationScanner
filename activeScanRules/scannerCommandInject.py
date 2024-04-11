import requests
import re
import time

from activeScanRules.activeScanner import ActiveScanner

class ScanCommandInject(ActiveScanner):
    def __init__(self, host_os=None, visited_urls=None, log_file=None):
        self.host_os = host_os
        super().__init__(visited_urls, log_file)

    def initialise_commands(self):
        # all payloads working with matching regex
        linux_payloads = [
            r"mkdir abcdefghijkl && ls",
            r"touch abcdefghijkl.txt && ls",
            r"mkdir abcdefghijkl; ls",
            r"touch abcdefghijkl.txt; ls",
            r"ls /",
            r"id",
            r"cat /etc/passwd",
            r"uname -a"
        ]
        windows_payloads = [
            r"mkdir abcdefghijkl && dir",
            r"echo. > abcdefghijkl.txt && dir",
            r"dir C:\\",
            r"whoami",
            r"systeminfo",
            r"type C:\Windows\system.ini"
        ]
        if self.host_os == "unix":
            return linux_payloads
        elif self.host_os == "windows":
            return windows_payloads
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_payloads

    def initialise_injection_characters(self):
        injection_characters = [r";", r"\n", r"&", r"|", r"&&", r"||", r")"
        ]
        return injection_characters

# use tabs to pass waf %09 or  ${IFS}
    def initialise_payload_response_patterns(self):
        linux_command_patterns = [
            re.compile(r"uid=[0-9]+.*gid=[0-9]+.*groups=.*"), # id
            re.compile(r"root:.*:0:0:.*"), # cat passwd
            re.compile(r"abcdefghijlk"), #touch and mkdir
            re.compile(r"bin.*"), # ls /
            re.compile(r"Linux .+ \d+\.\d+\.\d+[-\w]* .*"),  # Pattern for 'uname -a'
        ]
        windows_command_patterns = [
            re.compile(r"abcdefghijlk.*"),
            re.compile(r"abcdefghijlk.txt.*"),
            re.compile(r"Volume in drive C has no label."),
            re.compile(r"User Name"),
            re.compile(r"Host Name"),
            re.compile(r"Directory of C:\\Windows"),
            re.compile(r"^\[drivers]$"),
        ]

        if self.host_os == "unix":
            return linux_command_patterns
        elif self.host_os == "windows":
            return windows_command_patterns
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_command_patterns

    def initialise_payloads(self):
        injection_characters = self.initialise_injection_characters()
        commands = self.initialise_commands()
        payloads = []
        for command in commands:
            for injection_character in injection_characters:
                payload = injection_character + command
                payloads.append(payload)
        return payloads

    def test_payloads(self, target_url, form_fields):
        # Open the file containing command injection payloads
        payloads = self.initialise_payloads()
        # Initialise a flag to track if any potential vulnerability is found
        potential_vulnerability_found = False
        for payload in payloads:
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
            self.test_blind_command_injection(target_url, form_fields)

    def check_response(self, response, payload, url):
        # Check if response indicates successful injection
        if response.status_code == 200:
            # Check if the response contains common command injection error messages or patterns
            for pattern in self.initialise_payload_response_patterns():
                if pattern.search(response.text):
                    self.logger.warning(
                        f"\tPotential command injection vulnerability found at: {url} with payload {payload}")
                    return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")
        return False

    def test_blind_command_injection(self, target_url, form_fields):
        self.logger.info("\tTesting blind command injection")
        try:
            # Send initial request to get baseline response time
            start_time = time.time()
            response = requests.get(target_url)
            end_time = time.time()
            baseline_time = end_time - start_time

            # Send request with sleep command payload
            payload = ";sleep 5"  # Adjust the sleep duration as needed
            form_data = {}
            for field_name, _ in form_fields:
                form_data[field_name] = payload

            form_method = form_data.get('method', 'post').lower()
            action = form_data.get('action', target_url)
            inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
            post_data = {}
            for input_name in inputs:
                post_data[input_name] = form_data[input_name]

            if form_method == 'post':
                start_time = time.time()
                response = requests.post(action, data=post_data)
                end_time = time.time()
            else:
                start_time = time.time()
                response = requests.get(action, params=post_data)
                end_time = time.time()

            execution_time = end_time - start_time

            # Compare execution time with baseline
            if execution_time > baseline_time + 4:  # Adjust the threshold as needed
                self.logger.warning(f"\tPotential blind command injection vulnerability found at: {target_url} with payload {payload}")
            else:
                self.logger.info(f"\tNo potential blind command injection vulnerability found at: {target_url}")

        except Exception as e:
            self.logger.error(f"\tAn error occurred during blind command injection test: {e}")