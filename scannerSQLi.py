import requests
from bs4 import BeautifulSoup


class ScanSQLInject:
    def __init__(self):
        super().__init__()

    def start_sql_inject_scan(self):
        # Open the file containing target URLs
        print("opening file")
        with open("output/test_url.txt", "r") as file:
            for target_url in file:
                target_url = target_url.strip()  # Remove whitespace characters
                # Send HTTP request to get HTML content
                html_content = self.get_html_content(target_url)

                # Extract form fields from HTML content
                form_fields = self.extract_form_fields(html_content)

    def get_html_content(self, target_url):
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to retrieve HTML content from {target_url}. Status code: {response.status_code}")
                return None
        except Exception as e:
            print(f"An error occurred while retrieving HTML content from {target_url}: {e}")
            return None

    def extract_form_fields(self, html_content):
        form_fields = []
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        print(forms)
        for form in forms:
            fields = form.find_all(['input', 'textarea'])
            for field in fields:
                field_name = field.get('name')
                field_type = field.get('type') or 'text'
                form_fields.append((field_name, field_type))
        return form_fields
