import requests
import re
import logging
from activeScanRules.fileInclusionScanRules.scanFileInclusion import FileInclusionScanner

class ScanLocalFileInclusion(FileInclusionScanner):
    def __init(self, visited_urls="output/testURLs.txt", log_file=None):
        super().__init__(visited_urls, log_file)
