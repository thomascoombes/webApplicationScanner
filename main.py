import argparse
import logging
import time
import os

from nmapScan import NmapScanner
from spider.spider import Spider
from activeScanRules.scannerSQLInject import ScanSQLInject
from activeScanRules.scannerCommandInject import ScanCommandInject
from activeScanRules.scannerReflectedXSS import ScanReflectedXSS
from activeScanRules.scannerStoredXSS import ScanStoredXSS
from activeScanRules.fileInclusionScanRules.scannerLocalFileInclusion import ScanLocalFileInclusion
from activeScanRules.fileInclusionScanRules.scannerRemoteFileInclusion import ScanRemoteFileInclusion
from activeScanRules.scannerXXEInject import ScanXXEInject
from activeScanRules.scannerVerbTampering import ScanVerbTampering


def clear_output_directory(output_directory2):
    if output_directory2 and os.path.exists(output_directory2):
        for filename in os.listdir(output_directory2):
            file_path = os.path.join(output_directory2, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    clear_output_directory(file_path)  # Recursively clear subdirectories
            except Exception as e:
                print(f"Failed to delete {file_path}: {e}")
    else:
        print("Output directory does not exist.")


def make_test_file(output_directory2):
    # Create the output directory if it doesn't exist
    mutillidae_test_urls = ["http://192.168.232.129:80/",
            "http://192.168.232.129:80/mutillidae/",
            "http://192.168.232.129:80/mutillidae/index.php?page=home.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=login.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=user-info.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=register.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=dns-lookup.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=view-someones-blog.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=arbitrary-file-inclusion.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=text-file-viewer.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=set-background-color.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=html5-storage.php",
            "http://192.168.232.129:80/mutillidae/?page=add-to-your-blog.php",
            "http://192.168.232.129:80/mutillidae/index.php?page=capture-data.php"
            ]
    dvwa_test_urls = [
                    "http://192.168.232.129/dvwa/vulnerabilities/xss_r/",
                    "http://192.168.232.129/dvwa/vulnerabilities/xss_s/",
                    "http://192.168.232.129/dvwa/vulnerabilities/sqli/"
    ]
    # Define the path to the testURLs.txt file
    file_path2 = os.path.join(output_directory2, "testURLs.txt")
    # Write the URLs to the file
    with open(file_path2, "a") as file:
        for url in mutillidae_test_urls: #change depending on url subset required
            file.write(url + "\n")


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
                                                                       "scanning", required=False)
    parser.add_argument("-H", "--host-os", choices=["unix", "windows"], default="unix",
                        help="Set the host operating system type (Unix or Windows)", required=False)

    parser.add_argument("-a", "--aggression", type=int, default=4, choices=range(1, 7),
                        help="Set the aggression level (1-6, default: 4)", required=False)
    parser.add_argument("-U", "--Username", default=None, help="Set the username for authenticated attacks",
                        required=False)
    parser.add_argument("-P", "--Password", default=None, help="Set the password for authenticated attacks",
                        required=False)

    # Parse the command-line arguments
    args = parser.parse_args()

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






    # Create directory for the target if it doesn't exist, clear it if it does exist
    target_directory = os.path.join("output", args.target.replace("://", "_").replace("/", "_"))
    os.makedirs(target_directory, exist_ok=True)
    # Set output directory path
    output_directory = target_directory
    clear_output_directory(output_directory)
    # make a test file with a smaller subset of urls
    make_test_file(output_directory)

    # Make objects
    nmap = NmapScanner(args.target, args.port, args.aggression)
    spider = Spider(args.target, args.port, args.depth, args.exclude, args.Username, args.Password,
                    output_directory=output_directory)
    sql_inject = ScanSQLInject(visited_urls=output_directory + "/testURLs.txt",
                               log_file=output_directory + "/sql_inject.log")
    command_inject = ScanCommandInject(args.host_os, visited_urls=output_directory + "/testURLs.txt",
                                       log_file=output_directory + "/command_inject.log")
    reflected_xss = ScanReflectedXSS(visited_urls=output_directory + "/testURLs.txt",
                                     log_file=output_directory + "/reflected_xss.log")
    stored_xss = ScanStoredXSS(visited_urls=output_directory + "/testURLs.txt",
                               log_file=output_directory + "/stored_xss.log")
    verb_tampering = ScanVerbTampering(visited_urls=output_directory + "/testURLs.txt",
                                       log_file=output_directory + "/verb_tampering.log")
    remote_file_inclusion = ScanRemoteFileInclusion(visited_urls=output_directory + "/testURLs.txt", log_file=output_directory + "/remote_file_include.log")

    # Start scans
    #nmap.nmap_web_app()
    #spider.spider()
    sql_inject.start_scan()
    # command_inject.start_scan()
    # reflected_xss.start_scan()
    # stored_xss.start_scan()
    # verb_tampering.start_scan()
    remote_file_inclusion.start_scan()




