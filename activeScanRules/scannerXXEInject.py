import requests
from bs4 import BeautifulSoup
import os


class ScanXXEInject:

    def __init__(self, visited_urls="output/visited_urls.txt"):
        self.targets_file = visited_urls