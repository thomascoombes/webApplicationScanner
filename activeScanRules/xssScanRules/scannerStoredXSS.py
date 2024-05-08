from selenium.webdriver.common.by import By
from selenium.common import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
import re
from bs4 import BeautifulSoup
import random
import hashlib

from activeScanRules.xssScanRules.scannerXSS import ScanXSS

class ScanStoredXSS(ScanXSS):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)
        self.driver = None
        self.proxies = {'http': 'http://127.0.0.1:8080',
                   'https': 'http://127.0.0.1:8080'}

    def get_urls(self):
        with open(self.targets_file, "r") as file:
            lines = file.readlines()
        return lines

    def generate_random_safe_value(self):
        # A longer list of random words
        word_list = [
            "apple", "banana", "orange", "grape", "kiwi", "melon", "peach", "pear", "plum", "strawberry",
            "apricot", "blueberry", "cherry", "coconut", "fig", "guava", "lemon", "lime", "mango", "pineapple",
            "raspberry", "watermelon", "avocado", "blackberry", "cantaloupe", "cranberry", "elderberry", "papaya",
            "passionfruit", "pomegranate", "tangerine", "kiwifruit", "starfruit", "lychee", "dragonfruit", "persimmon",
            "boysenberry", "nectarine", "plantain", "quince", "rhubarb", "soursop", "ugli fruit", "durian", "jackfruit",
            "breadfruit", "longan", "salak", "cherimoya", "ackee", "custard apple", "rambutan", "sapodilla", "langsat"
        ]

        # Select a random word from the list
        random_word = random.choice(word_list)

        # Hash the selected word using MD5 (you can use other hash algorithms if needed)
        safe_value = hashlib.md5(random_word.encode()).hexdigest()

        return safe_value


    def start_scan(self):
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        lines = self.get_urls()
        for target_url in lines:
            #print(target_url)
            target_url = target_url.strip()
            html_content = self.get_html_content(target_url)
            form_fields = self.extract_form_fields(html_content)
            if not form_fields:
                self.logger.info(f"\tNo forms found on {target_url}. Skipping...")
                #print(f"\033[36m[+] No forms found on {target_url}. Skipping...\033[0m")
                continue
            print(f"Sending safe value to {target_url} and spidering application")
            potentially_vulnerable_urls = self.send_safe_value(target_url, form_fields)

            if len(potentially_vulnerable_urls) != 0:
                vulnerable_urls, payload = self.send_xss_payload(target_url, form_fields, potentially_vulnerable_urls)
                if vulnerable_urls is not None:
                    for url in vulnerable_urls:
                        self.logger.warning(
                            f"Reflected Cross Site Scripting vulnerability found at: "
                            f"{url} with payload: <scrIpt>alert('XSS')</sCriPt>")
                        print(
                            f"\033[31m[+] Reflected Cross Site Scripting vulnerability found at: "
                            f"{url} with payload: {payload}\033[0m")
            #else:
            #    self.logger.info(f"No Stored Cross Site Scripting vulnerabilities found")
            #    print(f"\033[32m[+] No Stored Cross Site Scripting vulnerabilities found\033[0m")

    def send_safe_value(self, target_url, form_fields):
        safe_value = self.generate_random_safe_value()
        method = form_fields[0][2].upper()
        form_data = {}
        for field_tuple in form_fields:
            form_data[field_tuple[0]] = safe_value
        try:
            action = form_data.get('action', target_url)
            inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
            post_data = {}
            for input_name in inputs:
                post_data[input_name] = form_data[input_name]
            response = None
            if method == 'POST':
                response = requests.post(action, data=post_data) # , proxies=self.proxies
            elif method == 'GET':
                response = requests.get(action, params=post_data) # , proxies=self.proxies
            if response is not None:
                potentially_vulnerable_urls = self.check_safe_value_locations(safe_value)
                return potentially_vulnerable_urls

        except Exception as e:
            self.logger.error(
                f"\tAn error occurred while sending form with save value to {target_url}: {e}")

    def check_safe_value_locations(self, safe_value):
        pattern = re.compile(safe_value)
        urls = self.get_urls()
        #print(len(urls))
        potentially_vulnerable_urls = []
        for url in urls: # for each url
            url = url.strip()
            try:
                response = self.get_html_content(url) # get response content
                match = pattern.search(response)
                if match: # if safe value in response
                    potentially_vulnerable_urls.append(url) # add that url to potentially vulnerable urls
                #else: #if safe value not in response
                #    self.search_forms_for_safe_value(response, url)

            except Exception as e:
                #print(f"{e} for {url}")
                pass
        return potentially_vulnerable_urls

    def search_forms_for_safe_value(self, response, url):
        form_fields = self.extract_form_fields(response)
        if form_fields:
            # Check if the form has a <select> element
            select_field = None
            for field in form_fields:
                if field[0] == 'select':
                    select_field = field
                    break
            # If a select field is found, choose all options
            if select_field:
                form_data = {}
                form_data[select_field[0]] = [option[1] for option in select_field[3]]  # List of all options
                # Submit the form with all options selected
                action = select_field[1].get('action', response.url)
                method = select_field[1].get('method', 'GET')
                # Submit the form based on the method (GET or POST)
                if method.upper() == 'POST':
                    response = requests.post(action, data=form_data) # , proxies=self.proxies
                else:
                    response = requests.get(action, params=form_data)# , proxies=self.proxies
                return response
        return None

    def send_xss_payload(self, target_url, form_fields, potentially_vulnerable_urls):
        proxies = {'http': 'http://127.0.0.1:8080',
                   'https': 'http://127.0.0.1:8080'}

        payload = "<scrIpt>alert(\"XSS\")</sCriPt>"
        method = form_fields[0][2].upper()
        form_data = {}
        for field_tuple in form_fields:
            form_data[field_tuple[0]] = payload
        try:
            action = form_data.get('action', target_url)
            inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
            post_data = {}
            for input_name in inputs:
                post_data[input_name] = form_data[input_name]
            response = None
            if method == 'POST':
                response = requests.post(action, data=post_data)# , proxies=self.proxies
            elif method == 'GET':
                response = requests.get(action, params=post_data)# , proxies=self.proxies

            if response is not None:
                vulnerable_urls = self.check_xss_payload_locations(potentially_vulnerable_urls)
                return vulnerable_urls, payload

        except Exception as e:
            self.logger.error(
                f"\tAn error occurred while sending form with XSS payload to {target_url}: {e}")

    def check_xss_payload_locations(self, potentially_vulnerable_urls):
        vulnerable_urls = []
        self.start_driver()
        for url in potentially_vulnerable_urls:
            url = url.strip()
            self.driver.get(url)
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert.accept()
                vulnerable_urls.append(url)
            except TimeoutException as e:
                pass
        self.close_browser()
        return vulnerable_urls