from selenium.common import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from activeScanRules.xssScanRules.scannerXSS import ScanXSS

class ScanReflectedXSS(ScanXSS):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)
        self.driver=None

    def initialise_payloads(self):
        payloads = [
            r"<scrIpt>alert('XSS')</sCriPt>",
            '<scrIpt>alert("XSS")</sCriPt>',
            r"<scrIpt>alert()</sCriPt>",
            r"<img src=x onerror=prompt()>",
            r"<img src=x onerror=console.log(1);>",
            r"<svg onload=alert(1)>",
            r"<b onMouseOver=alert(1);>test</b>",
            r"accesskey='x' onclick='alert(1)' b",
            r"button onclick='alert(1)'"
        ]
        return payloads

    def test_payloads(self, target_url, form_fields):
        payloads = self.initialise_payloads()
        potential_vulnerability_found = False
        for payload in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            # Prepare form data with command injection payload
            form_data = {}
            parameters_added = False
            for field_tuple in form_fields:
                field_name = field_tuple[0]
                if field_name != 'page':  # Skip the 'page' parameter
                    form_data[field_name] = payload

            #print(form_data)
            try:
                # Get the form method (post or get)
                form_method = form_fields[0][2]
                # Get the action URL or set it to the target URL if not found
                action = form_data.get('action', target_url)

                # Extract input fields from the form_data
                inputs = [key for key in form_data.keys() if key != 'method' and key != 'action']
                # Prepare post data for submission
                post_data = {}
                for input_name in inputs:
                    post_data[input_name] = form_data[input_name]
                # print(f"form data {form_data}\n post data {post_data}")
                vulnerability_found = self.check_reflections(action, form_method, post_data, form_fields)
                if vulnerability_found:
                    self.logger.warning(
                        f"Reflected Cross Site Scripting vulnerability found at: {action} with payload: {payload}")
                    print(
                        f"\033[31m[+] Reflected Cross Site Scripting vulnerability found at: {action} with payload: {payload}\033[0m")
                    potential_vulnerability_found = True
                    break
            except Exception as e:
                self.logger.error(
                    f"\tAn error occurred while sending form with XSS payload to {target_url}: {e}")
        # After testing all payloads, if no potential vulnerability is found, print the message
        if not potential_vulnerability_found:
            self.logger.info(f"No Reflected Cross Site Scripting vulnerability found at: {target_url}")
            print(f"\033[32m[+] No Reflected Cross Site Scripting vulnerability found at: {target_url}\033[0m")

    def check_reflections(self, action, form_method, post_data, form_fields):
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
                    """.format(" ".join([
                                                                 f'var input{index} = document.createElement("input"); input{index}.setAttribute("name", "{name}"); input{index}.value = "{value}"; form.appendChild(input{index});'
                                                                 for index, (name, value) in
                                                                 enumerate(post_data.items())]))
            # Execute the script
            self.driver.execute_script(script, action)
        else:
            # Construct URL with payload
            url_with_payload = action + '&' + '&'.join([f'{name}={value}' for name, value in post_data.items()])
            # print("payloaded url", url_with_payload)
            self.driver.get(url_with_payload)
        # Check for JavaScript pop-up
        try:
            WebDriverWait(self.driver, 2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert.accept()
            return True
        except TimeoutException:
            return False

