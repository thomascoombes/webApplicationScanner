import requests,json, random
from requests.auth import HTTPBasicAuth
import alienvault_interface
import time

while True:
    
    av = alienvault_interface.alienvault_intelligence()
    results = av.query_keyword('CVE-2020-13756')

    for i in results:
        print(i)
        break
    
    