import requests
import re
import logging
from activeScanRules.activeScanner import ActiveScanner

class ScanRemoteFileInclusion(ActiveScanner):
    def __init(self):
        super().__init__()
