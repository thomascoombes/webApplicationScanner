from bs4 import BeautifulSoup
import urllib.parse
import urllib.request
import requests

start_url = "http://192.168.232.129"
queued_urls = []
visited_urls = []
crawl_depth = 2
current_depth = 0


def crawl(url, current_depth):
    # this also doesn't work
    # the logic needs to be worked on with the depth
    #if current_depth <= crawl_depth and url not in visited_urls:

        #do indent

    # sends http request to url
    response = requests.get(url)
    # create bs object by parsing html content of web page from http response # this is where js parsing might be required
    soup = BeautifulSoup(response.text, 'html.parser')
    # locates all href tags in the html and adds it to list href
    href = soup.find_all('a', href=True)
    # add the current url to the visited list to make way for the active scan
    visited_urls.append(url)
    #loops through
    for relative_url in href:
        relative_url = relative_url['href']
        absolute_url = urllib.parse.urljoin(url, relative_url)
        queued_urls.append(absolute_url)
        print("Absolute URL:", absolute_url, "Current Depth")


        # so this should call it recursively, but it doesn't
        # crawl(absolute_url, depth + 1)


#first time calling it needs the start url
crawl(start_url, current_depth)

print('visited URLs:', visited_urls)
print("queued URLs:", queued_urls)
