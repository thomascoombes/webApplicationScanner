from bs4 import BeautifulSoup
import requests
import urllib.parse

import queue


class Spider:
    def __init__(self, target=None, port=None, scan_depth=1, username=None, password=None):
        self.target = 'http://' + target
        self.port = port
        self.scan_depth = scan_depth
        self.username = username
        self.password = password

        self.url_queue = []
        self.visited_urls = []
        self.current_depth=0

    def get_urls(self, url):

        if self.current_depth <= self.scan_depth and url not in self.visited_urls:
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                href = soup.find_all('a', href=True)
                self.visited_urls.append(url)

                for relative_url in href:
                    absolute_url = self.make_absolute(url, relative_url['href'])
                    self.url_queue.append(absolute_url)
                    self.current_depth = self.current_depth + 1
                    self.get_urls(absolute_url)

            except Exception as e:
                print(f"error visiting {url}: {e}")

    def make_absolute(self, base_url, relative_url):
        absolute_url = urllib.parse.urljoin(base_url, relative_url)

        return absolute_url


"""
    def is_external_url(self):
        parsed_target = urllib.parse(self.target)
        parsed_url = urlparse(url)

        # Check if the URL has a different scheme or netloc (domain) than the target
        return parsed_target.scheme != parsed_url.scheme or parsed_target.netloc != parsed_url.netloc


    response = requests.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            href = soup.find_all('a', href = True)
            for relative_url in href:
                relative_url = relative_url['href']
                #print(relative_url)
                absolute_url = self.target + relative_url
                #print(absolute_url)
                self.url_queue.append(absolute_url)    
    """
