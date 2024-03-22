from bs4 import BeautifulSoup
import urllib.parse
import urllib.request
import requests

start_url = "http://192.168.232.129"
queued_urls = []
visited_urls = []
out_of_scope_urls = []

crawl_depth = 2
#current_depth = 0
counter = 0

def send_request(url): #sends the http request, and returns the response
    response = requests.get(url)
    return response

def parse_response(response_text):
    # parses the http response to extract hrefs and returns list of hrefs
    soup = BeautifulSoup(response_text.text, 'html.parser')
    href = soup.find_all('a', href=True)
    return href

def add_to_visited(url): # add url to visited list
    visited_urls.append(url)
    return visited_urls

def add_out_of_scope_urls(url):
    #adds urls that have a depth => than max_depth to out_of_scope_urls
    out_of_scope_urls.append(url)
    return out_of_scope_urls

def make_absolute(url, relative_url):
    # combines start url with each href to make them absolute
    absolute_url = urllib.parse.urljoin(url, relative_url)
    print(absolute_url)
    return absolute_url

def queue_urls(url, href, current_depth):  # loop through href list and add absolute urls to queue
    for relative_url in href:
        relative_url = relative_url['href']
        absolute_url = make_absolute(url, relative_url)
        queued_urls.append((absolute_url, current_depth))


def spider(url, max_depth):
    #initialise the current depth of spider
    current_depth = 0
    #add start url to queued_urls
    queued_urls.append((start_url, current_depth))
    print(queued_urls)
    #loop through queued_urls
    while queued_urls:
        url, depth = queued_urls.pop(0)
        #check current depth within scope
        if current_depth < max_depth and url not in out_of_scope_urls:
            #call send_request func for http response with url
            response = send_request(url)
            #call parse_response func for href with response
            href = parse_response(response)
            #call add_to_visited func with url to store visited
            add_to_visited(url)
            #call queue_urls with url and href to store queued
            queue_urls(url, href, current_depth)
            current_depth = current_depth + 1

    print(current_depth)




if __name__ == "__main__":
    spider(start_url, crawl_depth)


#make 2d list for queue and depth
#current depth variable will increase in spider class
# add exclusions to the out_of_scope_urls list


"""
def spider(url, max_depth):
    #initialise the current depth of spider
    current_depth = 0
    #add start url to queued_urls
    queued_urls.append((start_url, current_depth))

    #loop through queued_urls
    for url in queued_urls:
        #check current depth within scope
        if current_depth < max_depth and url not in out_of_scope_urls:
            #call send_request func for http response with url
            response = send_request(url)
            #call parse_response func for href with response
            href = parse_response(response)
            #call add_to_visited func with url to store visited
            add_to_visited(url)
            #call queue_urls with url and href to store queued
            queue_urls(url, href, current_depth)
            current_depth = current_depth + 1

"""