from bs4 import BeautifulSoup
import requests
import urllib.parse
from urllib.parse import urlparse, urljoin
from lxml import html
from requests.adapters import HTTPAdapter
import os
from urllib3 import Retry


class Spider:
    def __init__(self, targets=None, port=None, scan_depth=0, exclusions=None, username=None, password=None, visited_file="visited_urls.txt"):
        self.port = port
        self.max_depth = scan_depth
        self.username = username
        self.password = password
        self.queued_urls = []
        self.visited_urls = set()
        self.out_of_scope_urls = set(exclusions) if exclusions else set()
        self.visited_file = visited_file
        self.session = self.create_session()
        self.clear_visited_file()

        for target in targets:
            target = "http://" + target + "/"
            self.enqueue_url(target, depth=0)

    def clear_visited_file(self):
        # Clear the contents of the visited URLs file
        with open(self.visited_file, "w") as file:
            file.write("")

    def create_session(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        return session

    def spider(self):
        while self.queued_urls:
            url, depth = self.dequeue_url()
            if depth <= self.max_depth or self.max_depth == -1:
                if url not in self.out_of_scope_urls and url not in self.visited_urls:
                    response = self.send_request(url)
                    if response is not None:
                        href = self.parse_response(response)
                        self.add_to_visited(url)
                        self.enqueue_urls(url, href, depth + 1)
            if not self.queued_urls:
                break
        print("Finished crawling. Total number of visited URLs:", len(self.visited_urls),
              "\nVisited URLs can be found in visited_urls.txt")

    def add_to_visited(self, url):
        self.visited_urls.add(url)
        with open(self.visited_file, "a") as file:
            file.write(url + "\n")

    def send_request(self, url):
        try:
            response = self.session.get(url)
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
                self.enqueue_url(absolute_url, depth)
            else:
                self.out_of_scope_urls.add(absolute_url)

    def make_absolute(self, base_url, relative_url):
        return urljoin(base_url, relative_url)

    def is_internal_url(self, base_url, absolute_url):
        base_netloc = urlparse(base_url).netloc
        absolute_netloc = urlparse(absolute_url).netloc
        return base_netloc == absolute_netloc
