import requests
import re

from activeScanRules.fileInclusionScanRules.scanFileInclusion import FileInclusionScanner

class ScanRemoteFileInclusion(FileInclusionScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

    # affix = %00 (null byte)
    def initialise_payload_prefixes(self):
        prefixes = [
            "",
            "http://",
            "HTTP://",
            "htTp://",
            "httP://",
            "https://",
            "HTTPS://",
            "htTps://",
            "httPs://",
            "httpS://",
            ""
        ]
        return prefixes

    def initialise_file_targets(self):
        remote_file_targets = [
            "www.google.com/",
            "www.google.com:80/",
            #"www.google.com/search?q=github",
            #"www.google.com:80/search?q=github"
        ]
        return remote_file_targets

    def initialise_file_patterns(self):
        remote_file_patterns = [
            re.compile("<title>Google</title>"),
            #re.compile("// Google Inc"),
            #re.compile("<div>Google Account</div>")
            #re.compile("<title>Google</title>"),
            #re.compile("<title>Google</title>"),
            #re.compile("<title\.\*\?Google\.\*\?/title>"),
            #re.compile("<title\.\*\?Google\.\*\?/title>")
        ]
        return remote_file_patterns

    def construct_payloads(self):
        prefixes = self.initialise_payload_prefixes()
        remote_file_targets = self.initialise_file_targets()
        payloads = []
        for target in remote_file_targets:
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
                self.logger.error(f"\tAn error occurred while testing remote file inclusion in URL parameter: {e}")

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
                        f"\tAn error occurred while testing remote file inclusion in URL parameter with null byte affixed: {e}")

        if not potential_vulnerability_found:
            self.logger.info(
                f"\tNo remote file inclusion vulnerability found in URL parameters at: {base_url}")
            print(f"\033[32m[+] No remote file inclusion vulnerability found at: {base_url}\033[0m")

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
            self.logger.info(f"\tNo remote file inclusion vulnerability found in forms at: {target_url}")
            print(f"\033[32m[+] No remote file inclusion vulnerability found in forms at: {target_url}\033[0m")

    def check_response(self, response, payload, url, html_content, attack_type):
        if response.status_code == 200:
            if response.text != html_content:
                for pattern in self.initialise_file_patterns():
                    if pattern.search(response.text):
                        self.logger.warning(f"Remote file inclusion vulnerability "
                                         f"found at: {url} with payload: {payload}")
                        print(f"\033[31m[+] Remote file inclusion vulnerability "
                                         f"found at: {url}  with payload: {payload} via {attack_type}\033[0m")
                        return True
        else:
            self.logger.error(f"Unexpected response code ({response.status_code}) for {url}")