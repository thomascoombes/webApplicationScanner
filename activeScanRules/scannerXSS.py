from urllib.parse import urlparse, parse_qs, urlencode
import requests
import re
from bs4 import BeautifulSoup
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium import webdriver
from selenium.common import TimeoutException
from selenium.webdriver import Firefox
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.common.by import By

from activeScanRules.activeScanner import ActiveScanner


class XSSScanner(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        payloads = [
            "<scrIpt>alert('XSS')</sCriPt>",

        ]
        return payloads

    """
                "<img src=x onerror=prompt()>",
                "<img src=x onerror=console.log(1);>",
                "<svg onload=alert(1)>",
                "<b onMouseOver=alert(1);>test</b>",
                "accesskey='x' onclick='alert(1)' b",
                "button onclick='alert(1)'/"
                """

    def initialise_payload_response_patterns(self):
        return

    def start_scan(self):
        # Open the file containing target URLs
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        self.driver = None

        # Initialize WebDriver with proxy settings
        firefox_options = FirefoxOptions()
        firefox_options.headless = True  # Set headless mode

        # Configure proxy
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = 'localhost:8080'  # Burp Suite proxy address
        proxy.ssl_proxy = 'localhost:8080'  # Burp Suite proxy address
        # firefox_options.proxy = proxy

        # Initialize Firefox WebDriver
        self.driver = webdriver.Firefox(options=firefox_options)

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
                    print(f"\033[36m[+] No forms found on {target_url}. Skipping...\033[0m")
                    continue
                #self.test_test_payload()
                self.test_payloads(target_url, form_fields)

    def test_payloads(self, target_url, form_fields):
        payloads = self.initialise_payloads()
        potential_vulnerability_found = False
        for payload in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            # Prepare form data with command injection payload
            form_data = {}
            for field_name, _ in form_fields:
                form_data[field_name] = payload
            try:
                # Get the form method (post or get)
                form_method = form_data.get('method', 'post').lower()
                # Get the action URL or set it to the target URL if not found
                action = form_data.get('action', target_url)
                # Extract input fields from the form_data
                inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                # Prepare post data for submission
                post_data = {}
                for input_name in inputs:
                    post_data[input_name] = form_data[input_name]

                proxies = {'http': 'http://127.0.0.1:8080',
                           'https': 'http://127.0.0.1:8080'}  # for burp testing purposes


                # print(f"form data {form_data}\n post data {post_data}")
                vulnerability_found = self.check_reflections(action, form_method, post_data, payload)
                if vulnerability_found:
                    potential_vulnerability_found = True
                    break

            except Exception as e:
                self.logger.error(
                    f"\tAn error occurred while sending form with XSS payload to {target_url}: {e}")

        # After testing all payloads, if no potential vulnerability is found, print the message
        if not potential_vulnerability_found:
            self.logger.info(f"\tNo XSS vulnerability found at: {target_url}")

    def check_reflections(self, action, form_method, post_data, payload):
        # Navigate to the target URL
        self.driver.get(action)
        # Submit the form with the payload
        if form_method == 'post':
            script = """
                        var form = document.createElement("form");
                        form.method = "POST";
                        form.action = arguments[0];
                        {0}
                        document.body.appendChild(form);
                        form.submit();
                    """.format(" ".join([f'var input{index} = document.createElement("input"); input{index}.setAttribute("name", "{name}"); input{index}.value = "{value}"; form.appendChild(input{index});'
                                                                 for index, (name, value) in
                                                                 enumerate(post_data.items())]))

            # Execute the script
            self.driver.execute_script(script, action)
        else:
            # Construct URL with payload
            url_with_payload = action + '?' + '&'.join([f'{name}={value}' for name, value in post_data.items()])
            # print("payloaded url", url_with_payload)
            self.driver.get(url_with_payload)

        # Check for JavaScript pop-up
        try:
            WebDriverWait(self.driver, 2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert.accept()
            self.logger.warning(
                f"\tPotential XSS vulnerability found at: {action} with {payload}")
            print(f"\033[31m[+] Potential XSS vulnerability found at: {action} with {payload}\033[0m")
            return True
        except TimeoutException:
            self.logger.info(f"No XSS vulnerability found at: {action}")
            print(f"\033[32m[+] No XSS vulnerability found at: {action}\033[0m")
            return False

    def close_browser(self):
        if self.driver:
            self.driver.quit()
        else:
            return

