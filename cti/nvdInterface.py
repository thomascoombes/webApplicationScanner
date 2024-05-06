import nvdlib
import datetime

class NvdIntelligence:

    def __init__(self, api_key=None):
        self.api_key = api_key

    def search_cve(self, keyword):
        limit = 3
        cpe_name = 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*'

        end_date = (datetime.datetime.now())
        start_date = (end_date - datetime.timedelta(days=112)).strftime('%Y-%m-%d 00:00')
        end_date = end_date.strftime('%Y-%m-%d 00:00')

        keyword = self.initialise_keywords(keyword)
        cves = nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date, keywordSearch=keyword, limit=limit, key=self.api_key)
        cves.reverse()
        return cves

    def search_cpe(self, cpe):
        limit=1
        cpe = nvdlib.searchCVE(cpeName=cpe, limit=limit, key=self.api_key)
        print("failed")
        return cpe


    def initialise_keywords(self, vulnerability_name):
        cleaned_name = vulnerability_name.lower().replace(" vulnerability", "")
        if cleaned_name == "sql injection":
            return "sql%20injection"
        elif cleaned_name == "command injection":
            return "command%20injection"
        elif cleaned_name == "reflected cross site scripting":
            return  "reflected%20xss"
        elif cleaned_name == "stored cross site scripting":
            return "stored%20xss"
        elif cleaned_name == "remote file inclusion":
            return "remote%20%20inclusion"
        elif cleaned_name == "local file inclusion":
            return "lfi"
        elif cleaned_name == "verb tampering":
            return "http%20verb%20tampering"
        elif cleaned_name == "xml external entity injection":
            return  "xml%20external%20entity%20injection"
        elif cleaned_name == "server side template injection":
            return "server%20side%20template%20injection"