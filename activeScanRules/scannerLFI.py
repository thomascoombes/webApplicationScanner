import requests
import re
import logging
from activeScanRules.activeScanner import ActiveScanner

class ScanLocalFileInclusion(ActiveScanner):
    def __init(self):
        super().__init__()
