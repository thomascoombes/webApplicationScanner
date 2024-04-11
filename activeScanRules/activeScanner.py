import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse, parse_qs, urlencode


class ActiveScanner:
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

        self.logger = self.configure_logging()
        # Open the file containing target URLs
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        with open(self.targets_file, "r") as file:
            for target_url in file:
                target_url = target_url.strip()  # Remove whitespace characters
                # Send HTTP request to get HTML content
                html_content = self.get_html_content(target_url)

                # Extract form fields from HTML content
                form_fields = self.extract_form_fields(html_content)

                # If no form fields are found, skip further processing for this URL
                if not form_fields:
                    self.logger.info(f"\tNo forms found on {target_url}. Skipping...")
                    continue

                # Send form with payloads
                self.test_payloads(target_url, form_fields)

    def get_html_content(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                self.logger.error(f"\tFailed to retrieve HTML content from {target_url}. Status code: {response.status_code}")
                return None
        except Exception as e:
            self.logger.error(f"\tAn error occurred while retrieving HTML content from {target_url}: {e}")
            return None

    def extract_form_fields(self, html_content):
        form_fields = []
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            fields = form.find_all(['input', 'textarea'])
            for field in fields:
                field_name = field.get('name')
                field_type = field.get('type') or 'text'
                form_fields.append((field_name, field_type))
        return form_fields

    def initialise_payloads(self):
        raise NotImplementedError("Subclasses must implement initialise_payloads method")

    def test_payloads(self, target_url, form_fields):
        raise NotImplementedError("Subclasses must implement test_payloads method")

    def test_payloads_in_url(self, target_url, url_params):
        raise NotImplementedError("Subclasses must implement test_payloads_in_url method")

    def test_payloads_in_forms(self, target_url, form_fields):
        raise NotImplementedError("Subclasses must implement test_payloads_in_forms method")

    def check_response(self, response, payload, url):
        raise NotImplementedError("Subclasses must implement check_response method")

    def extract_url_params(self, target_url):
        parsed_url = urlparse(target_url)
        return parse_qs(parsed_url.query)

    def construct_modified_url(self, target_url, url_params, payload):
        #extract possible url parameters to test payloads in
        modified_params = {}
        for key, value in url_params.items():
            modified_params[key] = payload
        modified_query = urlencode(modified_params)
        modified_url = target_url.split('?')[0] + '?' + modified_query
        return modified_url

    def get_base_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

