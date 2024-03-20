import argparse

from spider import Spider
from nmapScanner import Nmap
from mainScanner import ApplicationVulnerabilityScanner


def main():
    # Create an ArgumentParser object to handle command-line arguments
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    # Add command-line arguments for target and optional parameters
    parser.add_argument("-t", "--target", help="Target web application(s) (URL or IP)", required=True) #nargs='+',

    # the remaining arguments are not required
    #port
    parser.add_argument("-p", "--port", default=80, help="Set the port that the web application is running on",
                        required=False)
    #depth
    parser.add_argument("-d", "--depth", type=int, default=-1, help="Set the scan depth (default: 1)",
                        required=False)  # default of -1 specifies unlimited scan depth
    #aggression level
    parser.add_argument("-a", "--aggression", type=int, default=1, choices=range(1, 5),
                        help="Set the aggression level (1-4, default: 1)", required=False)
    #authenticated attacks
    #username
    parser.add_argument("-U", "--Username", default=None, help="Set the username for authenticated attacks",
                        required=False)
    #password
    parser.add_argument("-P", "--Password", default=None, help="Set the password for authenticated attacks",
                        required=False)

    # Parse the command-line arguments
    args = parser.parse_args()

    # Create an ApplicationVulnerabilityScanner object with the specified parameters
    scanner = ApplicationVulnerabilityScanner(args.target, args.port, args.depth, args.aggression, args.Username,
                                              args.Password)
    scanner.start_scan()

    # Create an nmap object
    nmap = Nmap(args.target, args.port)
    nmap.nmap_web_app()

    # Create a Spider object with the specified parameters
    #spider = Spider(args.target, args.port, args.depth, args.Username, args.Password)
    #spider.start_spider()


if __name__ == "__main__":
    main()
