import argparse
import time
from nmapScan import NmapScanner
from spider import Spider
from activeScanRules.scannerSQLInject import ScanSQLInject
from activeScanRules.scannerXssPersistent import ScanPersXSS
from activeScanRules.scannerXXEInject import ScanXXEInject



if __name__ == "__main__":
    # Create an ArgumentParser object to handle command-line arguments
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    # Add command-line arguments for target and optional parameters
    parser.add_argument("-t", "--target", help="Target web application(s) (URL or IP)", required=True)  # nargs='+',
    parser.add_argument("-p", "--port", default=80, help="Set the port that the web application is running on",
                        required=False)
    parser.add_argument("-d", "--depth", type=int, default=-1, help="Set the scan depth (default: None)",
                        required=False)
    parser.add_argument("-e", "--exclude", nargs='+', default=[], help="URLs that are out of scope, to exclude from "
                                                                       "scanning",
                        required=False)
    parser.add_argument("-a", "--aggression", type=int, default=4, choices=range(1, 7),
                        help="Set the aggression level (1-6, default: 4)", required=False)
    parser.add_argument("-U", "--Username", default=None, help="Set the username for authenticated attacks",
                        required=False)
    parser.add_argument("-P", "--Password", default=None, help="Set the password for authenticated attacks",
                        required=False)

    # Parse the command-line arguments
    args = parser.parse_args()

    # Create an ApplicationVulnerabilityScanner object with the specified parameters
    # scanner = ApplicationVulnerabilityScanner(args.target, args.port, args.depth, args.exclude, args.aggression, args.Username,
    #                                           args.Password)
    # scanner.start_scan()

    print("Scan started on target:", args.target, ":", args.port,
          "using the following parameters:")
    if args.depth == -1:
        print("Scan Depth: Full")
    else:
        print("Scan Depth", args.depth)

    print("Aggression Level:", args.aggression)
    if args.Username is not None and args.Password is not None:
        print("\nAuthentication")
        print("Username:", args.Username)
        print("Password", args.Password)
    elif args.Username is not None or args.Password is not None:
        print("Provide a full username password combination")
        args.exit(1)

    """"
    # Call nmap to run rmap scan
    nmap = NmapScanner(args.target, args.port, args.aggression)
    nmap.nmap_web_app()
    time.sleep(2)
    # Call Spider to perform URL crawling
    spider = Spider(args.target, args.port, args.depth, args.exclude, args.Username, args.Password)
    spider.spider()
    time.sleep(2)
    """
    # Call SQLiScanner to perform SQL injection scanning
    sql_inject = ScanSQLInject()
    sql_inject.start_sql_inject_scan()
    time.sleep(2)

    xss = ScanPersXSS()
    # xss.some_class()
    time.sleep(2)
    xxe = ScanXXEInject()
    # xxe.some_class()
