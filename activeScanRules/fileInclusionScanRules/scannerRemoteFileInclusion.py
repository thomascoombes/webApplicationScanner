import requests
import re

from activeScanRules.fileInclusionScanRules.scanFileInclusion import FileInclusionScanner

class ScanRemoteFileInclusion(FileInclusionScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

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
            "www.google.com/search?q=github",
            "www.google.com:80/search?q=github"
        ]
        return remote_file_targets

    def initialise_remote_file_patterns(self):
        remote_file_patterns = [
            re.compile("<title>Google</title>"),
            re.compile("<title>Google</title>"),
            re.compile("<title>Google</title>"),
            re.compile("<title\.\*\?Google\.\*\?/title>"),
            re.compile("<title\.\*\?Google\.\*\?/title>")
        ]
        return remote_file_patterns

    def initialise_payloads(self):
        prefixes = self.initialise_payload_prefixes()
        remote_file_targets = self.initialise_file_targets()
        payloads = []
        for prefix in prefixes:
            for target in remote_file_targets:
                payload = prefix + target
                payloads.append(payload)
        return payloads


    def test_payloads(self, base_url, url_params, html_content):
        if html_content is None:
            self.logger.error(f"\tFailed to retrieve HTML content from {base_url}. Skipping...")
            return
        potential_vulnerability_found = False
        payload_combinations = self.initialise_payloads()
        for payload in payload_combinations:
            try:
                modified_url = self.construct_modified_url(base_url, url_params, payload)
                self.logger.info(f"\tTesting payload: {payload} on {base_url} as {modified_url}")
                # print(f"Testing payload: {payload} on {base_url} as {modified_url}")
                # Send HTTP request to the modified URL
                response = requests.get(modified_url)
                if self.check_response(response, payload, modified_url, html_content):
                    # print("vuln found")
                    potential_vulnerability_found = True
                    break
            except Exception as e:
                self.logger.error(f"\tAn error occurred while testing remote file inclusion in URL parameter: {e}")
        if not potential_vulnerability_found:
            self.logger.info(
                f"\tNo remote file inclusion vulnerability found in URL parameters at: {base_url}")

    def check_response(self, response, payload, url, html_content):
        if response.status_code == 200:
            if response.text != html_content:
                for pattern in self.initialise_remote_file_patterns():
                    if pattern.search(response.text):
                        self.logger.warning(f"\tPotential remote file inclusion vulnerability "
                                         f"found at: {url} with payload: {payload}")
                        return True
        else:
            self.logger.error(f"Unexpected response code ({response.status_code}) for {url}")



