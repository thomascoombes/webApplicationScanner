import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


class XSSPersistentScanner:
    def __init__(self):
        self.vulnerable_urls = []

    def analyze_web_page(self, url, html_content):
        """
        Analyze the web page content for potential XSS vulnerabilities.

        Args:
            url (str): The URL of the web page.
            html_content (str): The HTML content of the web page.

        Returns:
            list: A list of vulnerable URLs found on the web page.
        """
        vulnerable_urls = []

        # Analyze URLs for potential XSS vulnerabilities
        vulnerable_urls += self.analyze_urls(url, html_content)

        # Analyze forms for potential XSS vulnerabilities
        vulnerable_urls += self.analyze_forms(url, html_content)

        return vulnerable_urls

    def analyze_urls(self, base_url, html_content):
        """
        Analyze URLs in the web page content for potential XSS vulnerabilities.

        Args:
            base_url (str): The base URL of the web page.
            html_content (str): The HTML content of the web page.

        Returns:
            list: A list of vulnerable URLs found in the web page content.
        """
        vulnerable_urls = []

        soup = BeautifulSoup(html_content, 'html.parser')
        links = soup.find_all('a', href=True)

        for link in links:
            url = urljoin(base_url, link['href'])
            if self.is_potentially_vulnerable(url):
                vulnerable_urls.append(url)

        return vulnerable_urls

    def analyze_forms(self, base_url, html_content):
        """
        Analyze forms in the web page content for potential XSS vulnerabilities.

        Args:
            base_url (str): The base URL of the web page.
            html_content (str): The HTML content of the web page.

        Returns:
            list: A list of vulnerable URLs found in the web page content.
        """
        vulnerable_urls = []

        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            action = form.get('action')
            if action:
                url = urljoin(base_url, action)
                if self.is_potentially_vulnerable(url):
                    vulnerable_urls.append(url)

        return vulnerable_urls

    def generate_stored_xss_payload(self):
        """
        Generate a payload for testing stored XSS vulnerabilities.

        Returns:
            str: The generated XSS payload.
        """
        # This is a simple example, you may need to customize the payload
        return '<script>alert("XSS Vulnerability!")</script>'

    def send_request(self, url, payload):
        """
        Send an HTTP request with the injected XSS payload and analyze the response.

        Args:
            url (str): The URL to send the request to.
            payload (str): The XSS payload to inject.

        Returns:
            bool: True if the response indicates a potential XSS vulnerability, False otherwise.
        """
        try:
            response = requests.post(url, data={'input': payload})
            if '<script>alert("XSS Vulnerability!")</script>' in response.text:
                return True
        except requests.RequestException:
            pass
        return False

    def is_potentially_vulnerable(self, url):
        """
        Check if the URL is potentially vulnerable to XSS attacks.

        Args:
            url (str): The URL to check.

        Returns:
            bool: True if the URL is not excluded and is potentially vulnerable, False otherwise.
        """
        if url in self.exclusions:
            return False

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            return False

        return True

    def test_vulnerabilities(self, urls):
        """
        Test the given list of URLs for XSS vulnerabilities.

        Args:
            urls (list): A list of URLs to test for vulnerabilities.

        Returns:
            list: A list of vulnerable URLs.
        """
        vulnerable_urls = []

        for url in urls:
            payload = self.generate_stored_xss_payload()
            if self.send_request(url, payload):
                vulnerable_urls.append(url)

        return vulnerable_urls

    def run_scan(self, urls):
        """
        Run the XSS persistent scan using the provided list of URLs.

        Args:
            urls (list): A list of URLs to scan for XSS vulnerabilities.

        Returns:
            list: A list of vulnerable URLs.
        """
        return self.test_vulnerabilities(urls)
