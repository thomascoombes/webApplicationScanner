import argparse
from spider import Spider
import sys


class ApplicationVulnerabilityScanner:
    def __init__(self, target=None, port=None, scan_depth=1, aggression_level=1, username=None, password=None):
        self.target = target
        self.port = port
        self.scan_depth = scan_depth
        self.aggression_level = aggression_level
        self.username = username
        self.password = password

    def start_scan(self):
        print("Scan started on target:", self.target, ":", self.port,
              "using the following parameters:")
        if self.scan_depth == -1:
            print("Scan Depth: Full")
        else:
            print("Scan Depth", self.scan_depth)

        print("Aggression Level:", self.aggression_level)
        if self.username is not None and self.password is not None:
            print("\nAuthentication")
            print("Username:", self.username)
            print("Password", self.password)
        elif self.username is not None or self.password is not None:
            print("Provide a full username password combination")
            sys.exit(1)

        # Call Spider to perform URL crawling
        spider = Spider(self.target, self.port, self.scan_depth, [], self.username, self.password)
        spider.spider()


if __name__ == "__main__":
    # Create an ArgumentParser object to handle command-line arguments
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    # Add command-line arguments for target and optional parameters
    parser.add_argument("-t", "--target", nargs='+', help="Target web application(s) (URL or IP)", required=True)
    parser.add_argument("-p", "--port", default=80, help="Set the port that the web application is running on",
                        required=False)
    parser.add_argument("-d", "--depth", type=int, default=-1, help="Set the scan depth (default: None)",
                        required=False)
    parser.add_argument("-e", "--exclude", nargs='+', default=[], help="URLs that are out of scope, to exclude from "
                                                                       "scanning",
                        required=False)
    parser.add_argument("-a", "--aggression", type=int, default=1, choices=range(1, 5),
                        help="Set the aggression level (1-4, default: 1)", required=False)
    parser.add_argument("-U", "--Username", default=None, help="Set the username for authenticated attacks",
                        required=False)
    parser.add_argument("-P", "--Password", default=None, help="Set the password for authenticated attacks",
                        required=False)

    # Parse the command-line arguments
    args = parser.parse_args()

    # Create an ApplicationVulnerabilityScanner object with the specified parameters
    scanner = ApplicationVulnerabilityScanner(args.target, args.port, args.depth, args.aggression, args.Username,
                                              args.Password)
    scanner.start_scan()
