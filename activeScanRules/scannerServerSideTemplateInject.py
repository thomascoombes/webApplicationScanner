

from activeScanRules.activeScanner import ActiveScanner
class ServerSideTemplateInjectionScanner(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)


    def test_payloads(self):
        return