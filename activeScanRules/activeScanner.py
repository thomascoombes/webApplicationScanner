import requests
from bs4 import BeautifulSoup
import os
import logging

class ActiveScanner:
    def __init__(self, visited_urls_file, potential_vulnerability_file):
        self.targets_file = visited_urls_file
        self.potential_vulnerability_file = potential_vulnerability_file
        self.clear_potential_vulns_file()
        self.logger = logging.getLogger(__name__)

    def clear_potential_vulns_file(self):
        # Clear the contents of the potential vulnerability file
        with open(self.potential_vulnerability_file, "w") as file:
            file.write("")

    def start_scan(self):
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
                    self.logger.info(f"No forms found on {target_url}. Skipping...\n")
                    continue

                # Send form with payloads
                payload_file = self.initialise_payloads()
                self.test_payloads(target_url, form_fields, payload_file)

    def get_html_content(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                self.logger.error(f"Failed to retrieve HTML content from {target_url}. Status code: {response.status_code}")
                return None
        except Exception as e:
            self.logger.error(f"An error occurred while retrieving HTML content from {target_url}: {e}")
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

    def test_payloads(self, target_url, form_fields, payload_file):
        raise NotImplementedError("Subclasses must implement test_payloads method")

    def record_potential_vulnerability(self, target_url, payload):
        with open(self.potential_vulnerability_file, "a") as file:
            file.write(target_url + "\n")
            self.logger.warning(f"Potential vulnerability detected at {target_url} with payload: {payload}")
