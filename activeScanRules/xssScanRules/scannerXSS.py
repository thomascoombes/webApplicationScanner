from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy, ProxyType

from activeScanRules.activeScanner import ActiveScanner

class ScanXSS(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)
        self.driver=None

    def start_driver(self):
        # Initialize WebDriver with proxy settings
        firefox_options = FirefoxOptions()
        firefox_options.headless = True  # Set headless mode

        # Configure proxy
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = 'localhost:8080'  # Burp Suite proxy address
        proxy.ssl_proxy = 'localhost:8080'  # Burp Suite proxy address
        #firefox_options.proxy = proxy # comment out if dont want to intercept requests

        # Initialize Firefox WebDriver
        self.driver = webdriver.Firefox(options=firefox_options)

    def start_scan(self):
        # Open the file containing target URLs
        self.logger.info(f"\nStarting {self.__class__.__name__} scan")
        # Initialize WebDriver with proxy settings
        self.start_driver()
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
                    #print(f"\033[36m[+] No forms found on {target_url}. Skipping...\033[0m")
                    continue
                # self.test_test_payload()
                self.test_payloads(target_url, form_fields)
        self.close_browser()

    def close_browser(self):
        if self.driver:
            self.driver.quit()
        else:
            return