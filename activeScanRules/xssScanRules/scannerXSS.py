from urllib.parse import urlparse, parse_qs, urlencode
import requests
import re
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common import TimeoutException
from selenium.webdriver import Firefox
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

from activeScanRules.activeScanner import ActiveScanner


class XSSScanner(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        payloads = [
            "<scrIpt>alert('XSS')</sCriPt>",
            "<img src=x onerror=prompt()>",
            "<img src=x onerror=console.log(1);>",
            "<svg onload=alert(1)>",
            "<b onMouseOver=alert(1);>test</b>",
            "accesskey='x' onclick='alert(1)' b",
            "button onclick='alert(1)'/",
        ]
        return payloads

    def initialise_payload_response_patterns(self):
        return

    def start_scan(self):
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

                self.test_test_payload()
                #self.test_payloads(target_url)


    def test_payloads(self, target_url):
        driver = Firefox()

        try:
            driver.get(target_url)
            for payload in self.initialise_payloads():
                html_content = driver.page_source
                soup = BeautifulSoup(html_content, 'html.parser')
                input_fields = soup.find_all()

                for input_field in input_fields:
                    xpath = f"//input[@name='{input_field.get('name')}']"
                    form_element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, xpath)))
                    form_element.clear()
                    form_element.send_keys(payload)
                    form_element.submit()

                    # Check if a JavaScript alert pops up
                    alert = driver.switch_to.alert
                    if alert.text == 'XSS':
                        print("XSS alert detected!")
                    # You can take further action here, such as logging or notifying.
                    else:
                        print("No XSS alert detected.")
                        alert.dismiss()
        finally:
            driver.quit()

    def check_response(self, response, payload, target_url):
        return


    def test_test_payload(self):
        driver = Firefox()
        try:
            driver.get("http://192.168.232.129/mutillidae/index.php?page=dns-lookup.php")

            payload = "<scrIpt>alert('XSS')</sCriPt>"
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'input')))


            input_fields = driver.find_elements(By.TAG_NAME, 'input')

            for input_field in input_fields:
                # Clear the input field and enter the payload
                input_field.clear()
                input_field.send_keys(payload)

                # Submit the form
                input_field.submit()

                # Check if a JavaScript alert pops up
                try:
                    alert = WebDriverWait(driver, 5).until(EC.alert_is_present())
                    if alert.text == 'XSS':
                        print("XSS alert detected!")
                        # You can take further action here, such as logging or notifying.
                    else:
                        print("No XSS alert detected.")
                    alert.dismiss()
                except TimeoutException:
                    print("No alert detected.")
        finally:
            driver.quit()
