import requests
from urllib.parse import urlparse, urljoin, parse_qs
from lxml import html
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3 import Retry
import os

class Spider:
    def __init__(self, target=None, port=None, scan_depth=0, exclusions=None, username=None, password=None, output_directory=None):
        self.port = port
        self.target = "http://" + target + ":" + str(self.port) + "/"

        self.max_depth = scan_depth

        self.username = username
        self.password = password

        self.output_directory = output_directory
        if output_directory:
            self.visited_file = os.path.join(output_directory, "visited_urls.txt")
        else:
            self.visited_file = "output/visited_urls.txt"
        self.clear_visited_file()

        self.queued_urls = []
        self.visited_urls = set()
        self.enqueue_url(self.target, depth=0)

        self.exclusions = exclusions
        self.out_of_scope_urls = set(exclusions) if exclusions else set()

        self.session = self.create_session()


    def clear_visited_file(self):
        # Clear the contents of the visited URLs file
        with open(self.visited_file, "w") as file:
            file.write("")

    def create_session(self):
        # Create a requests Session object
        session = requests.Session()

        # Define retry strategy for handling retires on different HTTP codes
        retry_strategy = Retry(
            total=4, # Total number of retries
            backoff_factor=1, #
            status_forcelist=[429, 500, 502, 503, 504],  # List of status codes that trigger a retry
            method_whitelist=["GET"] # # HTTP methods for which retries are allowed
        )

        # Create an HTTP adapter with the defined retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        # Mount the adapter to the session, specifying the protocol (http://)
        session.mount('http://', adapter)

        # Check if username and password are provided
        if self.username and self.password:
            # If provided, set HTTP basic authentication using the provided credentials
            session.auth = HTTPBasicAuth(self.username, self.password)

        return session

    def spider(self):
        print("\nStarting spider from:", self.target)
        print("Exclusions: (", len(self.out_of_scope_urls), ")", self.out_of_scope_urls)
        while self.queued_urls:
            url, depth = self.dequeue_url()
            if depth <= self.max_depth or self.max_depth == -1:
                if url not in self.out_of_scope_urls and url not in self.visited_urls:
                    response = self.send_request(url)
                    if response is not None:
                        # If response is a tuple, unpack it
                        if isinstance(response, tuple):
                            final_url, response = response
                            url = final_url  # Update URL to the final redirected URL
                        href = self.parse_response(response)
                        self.add_to_visited(url)
                        self.enqueue_urls(url, href, depth + 1)
            if not self.queued_urls:
                break
        print("Finished crawling. Total number of visited URLs:", len(self.visited_urls))

    def add_to_visited(self, url):
        self.visited_urls.add(url)
        with open(self.visited_file, "a") as file:
            file.write(url + "\n")

    def send_request(self, url):
        try:
            response = self.session.get(url, allow_redirects=True)  # Ensure redirects are allowed
            # Check if the response is a redirect
            if response.history:
                # If there are redirections, get the final URL after all redirects
                final_url = response.url
                print("Redirected to:", final_url, "by", url)
                return final_url, response
            else:
                # If no redirects, return the response object as usual
                return response
        except Exception as e:
            print(f"Error occurred while fetching {url}: {str(e)}")
            return None

    def parse_response(self, response):
        tree = html.fromstring(response.content)
        href = tree.xpath('//a/@href')
        return href

    def enqueue_url(self, url, depth):
        self.queued_urls.append((url, depth))

    def dequeue_url(self):
        return self.queued_urls.pop(0)

    def enqueue_urls(self, base_url, hrefs, depth):
        for relative_url in hrefs:
            relative_url = relative_url.strip()
            absolute_url = self.make_absolute(base_url, relative_url)
            if self.is_internal_url(base_url, absolute_url):
                if self.check_url_params(absolute_url):
                    self.enqueue_url(absolute_url, depth)
            else:
                self.out_of_scope_urls.add(absolute_url)

    def check_url_params(self, url):
        # Check if the URL has toggle parameters that have been encountered before
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            for param, values in query_params.items():
                # Check if the parameter value combination has been visited before
                if (parsed_url.path, param, tuple(values)) in self.visited_urls:
                    return False
                # Add the parameter value combination to the visited set
                self.visited_urls.add((parsed_url.path, param, tuple(values)))
        return True

    def make_absolute(self, base_url, relative_url):
        return urljoin(base_url, relative_url)

    def is_internal_url(self, base_url, absolute_url):
        base_netloc = urlparse(base_url).netloc
        absolute_netloc = urlparse(absolute_url).netloc
        return base_netloc == absolute_netloc