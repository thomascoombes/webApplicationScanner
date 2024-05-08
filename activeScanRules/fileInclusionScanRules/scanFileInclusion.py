from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import time

from activeScanRules.activeScanner import ActiveScanner

class FileInclusionScanner(ActiveScanner):
    def __init__(self, visited_urls_file, log_file=None):
        super().__init__(visited_urls_file, log_file)
        self.modified_params = None
        self.parsed_url = None

    def start_scan(self):
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        base_urls = []
        with open(self.targets_file, "r") as file:
            lines = file.readlines()
        print(f"\033[36m[+] Starting Form Attack\033[0m")
        for target_url in lines:
            target_url = target_url.strip()
            html_content_for_forms = self.get_html_content(target_url)
            form_fields = self.extract_form_fields(html_content_for_forms)
            if not form_fields:
                self.logger.info(f"\tNo forms found on {target_url}. Skipping...")
                #print(f"\033[36m[+] No forms found on {target_url}. Skipping...\033[0m")
                continue
            self.test_form_payloads(target_url, form_fields, html_content_for_forms)
        time.sleep(6)
        print(f"\033[36m[+] Starting URL Attack\033[0m")
        for target_url in lines:
            target_url = target_url.strip()
            base_url = self.get_base_url(target_url)
            url_params = self.extract_url_params(target_url)
            if base_url not in base_urls and url_params:
                html_content = self.get_html_content(base_url)
                self.test_payloads(base_url, url_params, html_content)
                base_urls.append(base_url)

    def get_base_url(self, url):
        self.parsed_url = urlparse(url)
        return self.parsed_url.scheme + "://" + self.parsed_url.netloc + self.parsed_url.path

    def extract_url_params(self, target_url):
        self.parsed_url = urlparse(target_url)
        return parse_qs(self.parsed_url.query)

    def construct_modified_url(self, target_url, url_params, payload):
        # extract possible url parameters to test payloads in
        self.modified_params = {}
        for key, value in url_params.items():
            self.modified_params[key] = payload
        modified_query = urlencode(self.modified_params)
        modified_url = target_url.split('?')[0] + '?' + modified_query
        return modified_url

    def initialise_payload_prefixes(self):
        raise NotImplementedError("Subclasses must implement initialise_payload_prefixes method")

    def initialise_file_targets(self):
        raise NotImplementedError("Subclasses must implement initialise_file_targets method")

    def construct_payloads(self):
        raise NotImplementedError("Subclasses must implement initialise_payloads method")

    def initialise_file_patterns(self):
        raise NotImplementedError("Subclasses must implement initialise_local_file_patterns method")

    def test_payloads(self, base_url, url_params, html_content):
        raise NotImplementedError("Subclasses must implement test_payloads method")

    def check_response(self, response, payload, url, html_content, attack_type):
        raise NotImplementedError("Subclasses must implement check_response method")

    def test_form_payloads(self, target_url, form_fields, html_content):
        raise NotImplementedError("Subclasses must implement test_form_payloads method")
