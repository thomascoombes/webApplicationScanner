import argparse
import os

from nmapScan import NmapScanner
from spider import Spider
from reportGenerator import ReportGenerator

from activeScanRules.scannerSQLInject import ScanSQLInject
from activeScanRules.scannerCommandInject import ScanCommandInject
from activeScanRules.scannerVerbTampering import ScanVerbTampering
from activeScanRules.scannerXXEInject import ScanXXEInject
from activeScanRules.scannerServerSideTemplateInject import ServerSideTemplateInjectionScanner
from activeScanRules.xssScanRules.scannerReflectedXSS import ScanReflectedXSS
from activeScanRules.xssScanRules.scannerStoredXSS import ScanStoredXSS

from activeScanRules.fileInclusionScanRules.scannerLocalFileInclusion import ScanLocalFileInclusion
from activeScanRules.fileInclusionScanRules.scannerRemoteFileInclusion import ScanRemoteFileInclusion

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


def load_excluded_urls(filename):
    excluded_urls = []
    with open(filename, 'r') as file:
        for line in file:
            url = line.strip()
            if url:
                excluded_urls.append(url)
    return excluded_urls


if __name__ == "__main__":
    #listen_for_pause()
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
    parser.add_argument("-ef", "--exclude-file", help="File containing URLs to exclude", required=False)
    parser.add_argument("-sd", "--start-dir", help="Start directory for scanning", required=False)
    parser.add_argument("-H", "--host-os", choices=["unix", "windows"], default="unix",
                        help="Set the host operating system type (Unix or Windows)", required=False)

    parser.add_argument("-a", "--aggression", type=int, default=4, choices=range(1, 7),
                        help="Set the aggression level (1-6, default: 4)", required=False)
    parser.add_argument("-U", "--Username", default=None, help="Set the username for authenticated attacks",
                        required=False)
    parser.add_argument("-P", "--Password", default=None, help="Set the password for authenticated attacks",
                        required=False)
    # maybe add support for .pdf .md .yaml .xlsx .db if there is time
    parser.add_argument("-of", "--output-format", choices=["txt", "html", "xml", "json", "csv"], default="txt",
                        help="Set the output format (txt, html, xml, json)", required=False)
    #add argument for including threat intel & api key
    parser.add_argument("-cti", "--include-cyber-threat-intelligence", action="store_true", help="Include Cyber Threat Intelligence \(CTI\) in the scan")
    parser.add_argument("-api", "--api-key", default=None, help="Set the API key to reach NVD cyber threat intelligence feed",
                        required=False)


    # Parse the command-line arguments
    args = parser.parse_args()
    if args.exclude_file:
        excluded_urls_from_file = load_excluded_urls(args.exclude_file)
        args.exclude.extend(excluded_urls_from_file)

    print("\nStarting Dynamic Application Security Testing\n")
    print("\033[93m     (()__(()")
    print("     /       \\")
    print("    ( /    \\  \\")
    print("     \\ o o    /")
    print("     (_()_)__/ \\")
    print("    / _,==.____ \\")
    print("   (   |--|      )")
    print("   /\\_.|__|'-.__/\\_")
    print("  / (        /     \\")
    print("  \\  \\      (      /")
    print("   )  '._____)    /")
    print("(((____.--(((____/\033[0m")
    print("Gizmo the Application Security Testing Bear\nPlease bear with Gizmo as he conducts his scan")
    print("")
    print(f"\033[33mScan started on target using the following parameters:\033[0m")
    print(f"\033[33m[+] Target: {args.target}\033[0m")
    print(f"\033[33m[+] Port: {args.port}\033[0m")
    if args.depth == -1:
        print(f"\033[33m[+] Scan Depth: Full")
    else:
        print(f"\033[33m[+] Scan Depth: {args.depth}\033[0m")

    print(f"\033[33m[+] Aggression Level: {args.aggression}\033[0m")
    print("\033[33m[+] Exclusions: \033[0m")
    for exclusion in args.exclude:
        print(f"\t\033[33m{exclusion}\033[0m")
    print(f"\033[33m[+] Host OS: {args.host_os}\033[0m")
    if args.start_dir:
        print(f"\033[33m[+] Start Directory: {args.start_dir}\033[0m")
    if args.Username is not None and args.Password is not None:
        print("Authentication")
        print("Username:", args.Username)
        print("Password", args.Password)
    elif args.Username is not None or args.Password is not None:
        print("Provide a full username password combination")
        args.exit(1)
    print(f"\033[33m[+] Output Format: {args.output_format.upper()}\033[0m")


    # Create directory for the target if it doesn't exist, clear it if it does exist
    target_directory = os.path.join("output", args.target.replace("://", "_").replace("/", "_"))
    os.makedirs(target_directory, exist_ok=True)
    # Set output directory path
    output_directory = target_directory
    clear_output_directory(output_directory)
    report = output_directory + "/" + args.target.replace("://", "_").replace("/", "_") + "." + args.output_format


    visited_urls = output_directory + "/visited_urls.txt"


    # Make objects
    nmap = NmapScanner(args.api_key, args.target, args.port, args.aggression, log_file=output_directory + "/nmap.txt")
    spider = Spider(args.target, args.port, args.depth, args.exclude, args.start_dir, args.Username, args.Password, output_directory=output_directory)

    sql_inject = ScanSQLInject(visited_urls=visited_urls, log_file=output_directory + "/SQL_Injection.log")
    command_inject = ScanCommandInject(args.host_os, visited_urls=visited_urls, log_file=output_directory + "/Command_Injection.log")
    verb_tampering = ScanVerbTampering(visited_urls=visited_urls, log_file=output_directory + "/Verb_Tampering.log")
    rfi = ScanRemoteFileInclusion(visited_urls=visited_urls, log_file=output_directory + "/Remote_File_Inclusion.log")
    lfi = ScanLocalFileInclusion(args.host_os, visited_urls=visited_urls, log_file=output_directory + "/Local_File_Inclusion.log")
    xxe = ScanXXEInject(args.host_os, visited_urls=visited_urls, log_file=output_directory + "/XML_External_Entity_Injection.log")
    ssti = ServerSideTemplateInjectionScanner(visited_urls=visited_urls, log_file=output_directory + "/Server_Side_Template_Injection.log")
    rxss = ScanReflectedXSS(visited_urls=visited_urls, log_file=output_directory + "/Reflected_Cross_Site_Scripting.log")
    sxss = ScanStoredXSS(visited_urls=visited_urls, log_file=output_directory + "/Stored_Cross_Site_Scripting.log")

    print("")
    # Start scans
    print("\033[1;34m> Starting Nmap Scan\033[0m")
    nmap.nmap_web_app()

    print("\n\033[1;34m> Starting Spider\033[0m")
    spider.spider()

    print("\n\033[1;34m> Starting SQL Injection scan\033[0m")
    sql_inject.start_scan()
    print(f"\033[36m Finished SQL Injection scan\033[0m")

    print("\n\033[1;34m> Starting Command Injection scan\033[0m")
    command_inject.start_scan()
    print(f"\033[36m Finished Command Injection scan\033[0m")

    print("\n\033[1;34m> Starting Stored XSS scan\033[0m")
    sxss.start_scan()
    print(f"\033[36m Finished Stored XSS scan\033[0m")

    print("\n\033[1;34m> Starting Reflected XSS scan\033[0m")
    rxss.start_scan()
    print(f"\033[36m Finished Reflected XSS scan\033[0m")

    print("\n\033[1;34m> Starting Remote File Inclusion scan\033[0m")
    rfi.start_scan()
    print(f"\033[36m Finished Remote File Inclusion scan\033[0m")

    print("\n\033[1;34m> Starting Local File Inclusion scan\033[0m")
    lfi.start_scan()
    print(f"\033[36m Finished Local File Inclusion scan\033[0m")

    print("\n\033[1;34m> Starting Verb Tampering scan\033[0m")
    verb_tampering.start_scan()
    print(f"\033[36m Finished Verb Tampering scan\033[0m")

    print("\n\033[1;34m> Starting XXE Injection scan\033[0m")
    xxe.start_scan()
    print(f"\033[36m Finished XXE Injection scan\033[0m")

    print("\n\033[1;34m> Starting SSTI scan\033[0m")
    ssti.start_scan()
    print(f"\033[36m Finished SSTI scan\033[0m")

    RG = ReportGenerator(args.output_format, args.api_key, args.include_cyber_threat_intelligence,
                         log_file_location=output_directory, report_file=report, visited_urls=visited_urls,
                         nmap_log=output_directory + "/nmap.txt")

    print(f"\n\033[1;34m> Compiling {args.output_format.upper()} Report\033[0m")
    RG.start_report_compilation()
    print(f"\033[36m {args.output_format.upper()} Report Compiled. Can be found at {report}\033[0m")

