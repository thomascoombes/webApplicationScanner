import requests
from bs4 import BeautifulSoup
import os
import re

class ScanSQLInject:
    def __init__(self, visited_urls="output/testURLs.txt"):
        self.targets_file = visited_urls
        self.clear_potential_vulns_file()

    def clear_potential_vulns_file(self):
        # Clear the contents of the visited URLs file
        with open("output/potential_sqli_vulnerability.txt", "w") as file:
            file.write("")

    def start_sql_inject_scan(self):
        # Open the file containing target URLs
        print("\nStarting SQL Injection Scan")
        with open(self.targets_file, "r") as file:
            for target_url in file:
                target_url = target_url.strip()  # Remove whitespace characters
                # Send HTTP request to get HTML content
                html_content = self.get_html_content(target_url)

                # Extract form fields from HTML content
                form_fields = self.extract_form_fields(html_content)

                # If no form fields are found, skip further processing for this URL
                if not form_fields:
                    print(f"No forms found on {target_url}. Skipping...\n")
                    continue

                # Send form with payloads
                self.send_form_with_payloads(target_url, form_fields)

    def get_html_content(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to retrieve HTML content from {target_url}. Status code: {response.status_code}")
                return None
        except Exception as e:
            print(f"An error occurred while retrieving HTML content from {target_url}: {e}")
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

    def send_form_with_payloads(self, target_url, form_fields):
        # Define the directory containing payload files
        payloads_dir = "payloads/sqliPayloads/detect"
        payload_file = "payloads/sqliPayloads/detect/MySQL/MySQL.txt"

        if self.send_form_with_payload(target_url, form_fields, payload_file):
            return True
        """
        # Loop through each file in the payloads directory
        for root, _, files in os.walk(payloads_dir):
            for file in files:
                # Skip non-text files
                if not file.endswith(".txt"):
                    continue
                payload_file = os.path.join(root, file)
                # Send form with payloads from each file
                if self.send_form_with_payload(target_url, form_fields, payload_file):
                    return True  # Return True if a potential vulnerability is found
        """
        return False

    def send_form_with_payload(self, target_url, form_fields, payload_file):
        # Open the file containing SQL payloads
        with open(payload_file, "r") as payload_file:
            # Initialise a flag to track if any potential vulnerability is found
            potential_vulnerability_found = False
            for payload in payload_file:
                payload = payload.strip()  # Remove whitespace characters
                print(f"Testing payload: {payload} on {target_url}")
                # Prepare form data with SQL payload
                form_data = {}
                for field_name, _ in form_fields:
                    form_data[field_name] = payload

                try:
                    # Send POST request with form data
                    response = requests.post(target_url, data=form_data)

                    # Check if response indicates successful injection
                    if response.status_code == 200:
                        # Check if the response contains common SQL error messages or patterns
                        if (re.search(r'(error|syntax|exception|warning)', response.text, re.IGNORECASE) and
                                re.search(r'(SQL|mysql_fetch_array|mysqli_fetch_array)', response.text) and
                                payload in response.text):
                            print(
                                f"Potential SQL injection vulnerability found at: {target_url} with payload {payload} \n")
                            self.record_potential_vulnerability(target_url)
                            # Set the flag to indicate potential vulnerability found
                            potential_vulnerability_found = True
                            # No need to continue testing payloads if vulnerability found
                            break

                    else:
                        print(f"Unexpected response code ({response.status_code}) for {target_url}")

                except Exception as e:
                    print(f"An error occurred while sending form with SQL payload to {target_url}: {e}")

            # After testing all payloads, if no potential vulnerability is found, print the message
            if not potential_vulnerability_found:
                print(f"No potential vulnerability found at: {target_url}")

        return False

    def record_potential_vulnerability(self, target_url):
        # Write potential vulnerability to file
        with open("output/potential_sqli_vulnerability.txt", "a") as file:
            file.write(target_url + "\n")