import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse, parse_qs, urlencode


class FileInclusionScanner:
    def __init__(self, visited_urls_file, log_file=None):
        self.targets_file = visited_urls_file
        self.visited_base_urls = set()
        self.log_file = log_file
        #self.logger = self.configure_logging()

    def configure_logging(self):
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(logging.INFO)

        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        return logger


    def start_scan(self):
        # set up logger
        self.logger = self.configure_logging()
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        #
        base_urls = []
        with open(self.targets_file, "r") as file:
            for target_url in file:
                target_url = target_url.strip()
                base_url = self.get_base_url(target_url)
                url_params = self.extract_url_params(target_url)
                if base_url not in base_urls and url_params:
                    html_content = self.get_html_content(base_url)
                    self.test_payloads(base_url, url_params, html_content)
                    base_urls.append(base_url)

    def get_base_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

    def extract_url_params(self, target_url):
        parsed_url = urlparse(target_url)
        return parse_qs(parsed_url.query)

    def construct_modified_url(self, target_url, url_params, payload):
        # extract possible url parameters to test payloads in
        modified_params = {}
        for key, value in url_params.items():
            modified_params[key] = payload
        modified_query = urlencode(modified_params)
        modified_url = target_url.split('?')[0] + '?' + modified_query
        return modified_url

    def get_html_content(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                self.logger.error(
                    f"\tFailed to retrieve HTML content from {target_url}. Status code: {response.status_code}")
                return None
        except Exception as e:
            self.logger.error(f"\tAn error occurred while retrieving HTML content from {target_url}: {e}")
            return None

    def initialise_payloads(self):
        raise NotImplementedError("Subclasses must implement initialise_payloads method")

    def test_payloads(self, base_url, form_fields, html_content):
        raise NotImplementedError("Subclasses must implement test_payloads method")


