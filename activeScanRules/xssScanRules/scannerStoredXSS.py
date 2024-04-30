from selenium.webdriver.common.by import By
from selenium.common import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from activeScanRules.xssScanRules.scannerXSS import ScanXSS

class ScanStoredXSS(ScanXSS):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)
        self.driver = None

    def test_payloads(self, target_url, form_fields):
        try:
            # Navigate to the target URL
            self.driver.get(target_url)
            # Send dummy data to all form fields
            for field_name, _ in form_fields:
                try:
                    # Find the form field by name
                    input_field = self.driver.find_element(By.NAME, field_name)
                    # Check if it's a dropdown/select
                    if input_field.get_attribute('type') == 'select':
                        # If it's a dropdown, find the 'Show All' option and select it
                        show_all_option = input_field.find_elements(By.XPATH,
                                                                    "//option[contains(text(), 'Show All')]")
                        if show_all_option:
                            show_all_option[0].click()
                        else:
                            # If there's no 'Show All' option, select the first option
                            first_option = input_field.find_element(By.XPATH, "./option[1]")
                            first_option.click()
                    else:
                        # If it's not a dropdown, send dummy data
                        input_field.send_keys("dummy_data")
                except Exception as e:
                    self.logger.error(f"Error sending dummy data to form field '{field_name}': {e}")

            # Submit the form
            submit_buttons = self.driver.find_elements(By.XPATH, "//input[@type='submit']")
            if submit_buttons:
                submit_buttons[0].click()

            # Wait for page to load completely after form submission
            #WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

            # Check for JavaScript pop-up
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert.accept()
                self.logger.warning(f"Stored Cross Site Scripting vulnerability found at: {target_url}")
                print(f"\033[31m[+] Stored Cross Site Scripting vulnerability found at: {target_url}\033[0m")

            except TimeoutException:
                self.logger.info(f"No Stored Cross Site Scripting vulnerability found at: {target_url}")
                print(f"\033[32m[+] No Stored Cross Site Scripting vulnerability found at: {target_url}\033[0m")
        except Exception as e:
            self.logger.error(f"An error occurred while testing for stored XSS at {target_url}: {e}")