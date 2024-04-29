import requests
import re


from activeScanRules.activeScanner import ActiveScanner

class ServerSideTemplateInjectionScanner(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)


    def initialise_payloads(self):
        payloads = [
            [r"{7*7}", re.compile(r"49")],
            [r" ${7*7}", re.compile(r"49")],
            [r" {{7*7}}", re.compile(r"49")],
            [r"${{7*7}}", re.compile(r"49")],
            [r"#{3*3}", re.compile(r"49")],
            [r"#{ 7 * 7 }", re.compile(r"49")],
            [r"<%= 7 * 7 %>", re.compile(r"49")]
        ]
        return payloads

    def test_payloads(self, target_url, form_fields):
        # Initialise payload list
        payloads = self.initialise_payloads()
        # Initialise a flag to track if any potential vulnerability is found
        potential_vulnerability_found = False
        # Loop through payload list
        for payload, pattern in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            # Prepare form data with payload
            form_data = self.make_form_data(form_fields, payload)
            try:
                # Get the form method (post or get)
                form_method = form_data.get('method', 'post').lower()
                action = form_data.get('action', target_url)
                inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                # Prepare post data for submission
                post_data = self.make_post_data(inputs, form_data)
                # Check if method is post or get
                if form_method == 'post':
                    response = requests.post(action, data=post_data)
                else:
                    response = requests.get(action, params=post_data)
                # Call check response method to detect potential vulnerabilities
                if self.check_response(response, payload, pattern, target_url, action, form_fields, inputs):
                    potential_vulnerability_found = True
                    break  # Break out of the loop if vulnerability found
            # After testing all payloads, if no potential vulnerability is found, print the message
            except Exception as e:
                self.logger.error(
                    f"\tAn error occurred while sending form with SSTI payload to {target_url}: {e}")


        if not potential_vulnerability_found:
            self.logger.info(f"\tNo SSTI vulnerability found at: {target_url}")
            print(f"\033[32m[+] No SSTI vulnerability found at: {target_url}\033[0m")

    def check_response(self, response, payload, pattern, url, action, form_fields, inputs):
        if response.status_code == 200:
            if pattern.search(response.text): # Check if result of mathematical expression in response
                if self.verify_ssti(url, payload, action, form_fields, inputs): # Test
                    self.logger.warning(
                        f"\tSSTI vulnerability found at: {url} with payload: {payload}"
                    )
                    print(f"\033[31m[+] SSTI vulnerability found at: {url} with payload: {payload}\033[0m")
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")
        return False

    def verify_ssti(self, url, payload, action, form_fields, inputs):
        proxies = {'http': 'http://127.0.0.1:8080',
                   'https': 'http://127.0.0.1:8080'}  # for burp testing purposes

        # Test different mathematical expression to remove false positives
        verification_payload = payload.replace("7*7", "9*9")
        pattern = re.compile("81")
        form_data = self.make_form_data(form_fields, verification_payload)
        post_data = self.make_post_data(inputs, form_data)
        try:
            response = requests.post(action, data=post_data)# , proxies=proxies
            if pattern.search(response.text):
                return True
        except Exception as e:
            self.logger.error(
                f"\tAn error occurred while verifying SSTI at {url} with payload {verification_payload}: {e}")
            return False

    def finger_print_template_engine(self):
        # logic to fingerprint the template engine
        return


    # These 2 functions were made so the form data could be made correctly when verifying ssti
    def make_post_data(self, inputs, form_data):
        post_data = {}
        for input_name in inputs:
            post_data[input_name] = form_data[input_name]
        return post_data

    def make_form_data(self, form_fields, payload):
        form_data = {}
        for field_name, _ in form_fields:
            form_data[field_name] = payload
        return form_data


