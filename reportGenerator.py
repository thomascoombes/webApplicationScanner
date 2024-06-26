import os
import json
import re
import xml.etree.ElementTree as ET
import html

from cti.nvdInterface import NvdIntelligence

#maybe add support for .pdf .md .yaml .xlsx .db
class ReportGenerator:
    def __init__(self, output_format=None, api_key=None, include_cyber_threat_intelligence=None,
                 log_file_location=None, report_file=None, visited_urls=None, nmap_log=None):
        self.output_format = output_format
        self.api_key = api_key
        self.include_cyber_threat_intelligence = include_cyber_threat_intelligence
        self.log_file_locations = log_file_location + "/"
        self.report_file = report_file
        self.visited_urls = visited_urls
        self.log_files = ["SQL_Injection.log", "Command_Injection.log", "Reflected_Cross_Site_Scripting.log",
                          "Stored_Cross_Site_Scripting.log", "Remote_File_Inclusion.log", "Local_File_Inclusion.log", "Verb_Tampering.log",
                          "XML_External_Entity_Injection.log", "Server_Side_Template_Injection.log"]
        self.nvd = NvdIntelligence(self.api_key)
        self.nmap_log=nmap_log

    def start_report_compilation(self):
        log_vulnerabilities = self.extract_vulnerabilities()
        if self.output_format == "txt":
            self.write_txt_output(log_vulnerabilities)

        if self.output_format == "xml":
            self.write_xml_output(log_vulnerabilities)

        if self.output_format == "html":
            self.write_html_output(log_vulnerabilities)

        if self.output_format == "json":
            self.write_json_output(log_vulnerabilities)
        return

    def extract_number_of_visited_urls(self):
        num_lines = sum(1 for line in open(self.visited_urls))
        return num_lines

    def extract_vulnerabilities(self):
        vulns_dict = {}
        for filename in self.log_files:
            vulns_dict[self.clean_filename(filename)] = []
            if os.path.isfile(os.path.join(self.log_file_locations, filename)):
                with open(os.path.join(self.log_file_locations, filename), 'r') as file:
                    for line in file:
                        match = re.search(r'WARNING - (.*?) found at: (.*?) with payload: (.*)', line)
                        if match:
                            name = match.group(1)
                            url = match.group(2)
                            payload = match.group(3)
                            vulns_dict[self.clean_filename(filename)].append({'name': name, 'url': url, 'payload': payload})
        return vulns_dict

    def clean_filename(self, filename):
        filename = filename.replace('_', ' ').replace('.log', '')
        return filename

    # Function to write data to a text file
    def write_txt_output(self, vulns_dict):
        with open(self.report_file, 'w') as f:
            with open(self.nmap_log, 'r') as nmap_file:
                for line in nmap_file:
                    f.write(line)
            f.write(f"Total URLs Visited: {self.extract_number_of_visited_urls()}\n\n")
            for log_file, vulnerabilities in vulns_dict.items():
                f.write(f"{log_file} - {len(vulnerabilities)} vulnerabilities found\n")

                if vulnerabilities:
                    f.write(f"Description: {self.get_vulnerability_description(vulnerabilities[0]['name'])}\n")
                    for entry in vulnerabilities:
                        if entry:
                            f.write(f"URL: {entry['url']}\n")
                            f.write(f"Payload: {entry['payload']}\n")
                    f.write(f"Remediation Steps:\n{self.get_remediation_steps(vulnerabilities[0]['name'])}\n\n")
                    if self.include_cyber_threat_intelligence:
                        cwe_id = None
                        keyword = vulnerabilities[0]['name']
                        cves = self.nvd.search_cve(keyword)
                        if cves:
                            f.write(f"Recent {log_file} CVE's:\n")
                            for cve in cves:
                                f.write(f"CVE ID: {cve.id}\n")
                                for description in cve.descriptions:
                                    if description.lang == 'en':
                                        f.write(f"Description: {description.value}\n\n")
                            for cwe in cve.cwe:
                                if cwe.lang == 'en':
                                    cwe_id = cwe.value.replace('CWE-', '')
                                    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                                    f.write(f"Common Weakness Enumeration: {cwe_url}\n\n\n")
                                    break

                        else:
                            f.write(f"No {log_file} CVE's in the last 4 months\n\n\n")
                else:
                    f.write("\n\n")#No vulnerabilities found.
            #f.write("\n\n")

    def write_html_output(self, vulns_dict):
        with open(self.report_file, 'w') as f:
            f.write('<!DOCTYPE html>\n')
            f.write('<html>\n')
            f.write('<head>\n')
            f.write('<title>Vulnerability Report</title>\n')
            f.write('</head>\n')
            f.write('<body>\n')
            f.write("<h3>Nmap Log:</h3>\n\n")
            with open(self.nmap_log, 'r') as nmap_file:
                for line in nmap_file:
                    f.write(f"<p>{line}</p>\n")
            f.write(f"<h2>Total URLs Visited: {self.extract_number_of_visited_urls()}</h2>\n\n")
            for log_file, vulnerabilities in vulns_dict.items():
                f.write(f"<h3>{log_file} - {len(vulnerabilities)} vulnerabilities found</h3>\n")
                if vulnerabilities:
                    f.write(f"<p>Description: {self.get_vulnerability_description(vulnerabilities[0]['name'])}</p>\n")
                    f.write('<ul>\n')
                    for entry in vulnerabilities:
                        f.write('<li>\n')
                        f.write(f"<p>URL: {entry['url']}</p>\t")
                        escaped_payload = html.escape(entry['payload'])
                        f.write(f"<p>&emsp;Payload: {escaped_payload}</p>\n")
                        f.write('</li>\n')
                    f.write('</ul>\n')
                    f.write(f"<p>Remediation Steps:\n{self.get_remediation_steps(vulnerabilities[0]['name'])}</p>\n")
                    if self.include_cyber_threat_intelligence:
                        keyword = vulnerabilities[0]['name']
                        cves = self.nvd.search_cve(keyword)
                        cwe_id = None
                        if cves:
                            f.write(f"<p>Recent {log_file} CVE's:</p>\n")
                            for cve in cves:
                                f.write(f"<p>CVE ID: {cve.id}</p>\n")
                                for description in cve.descriptions:
                                    if description.lang == 'en':
                                        f.write(f"<p>Description: {description.value}</p>\n")
                            for cwe in cve.cwe:
                                if cwe.lang == 'en':
                                    cwe_id = cwe.value.replace('CWE-', '')
                            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                            f.write(f"<p>Common Weakness Enumeration: <a href='{cwe_url}'>{cwe_url}</a></p>\n\n")

                        else:
                            f.write(f"<p>No {log_file} CVE's in the last 4 months</p>\n\n")
                f.write("<br>\n")
            f.write('</body>\n')
            f.write('</html>\n')

    def write_xml_output(self, vulns_dict):
        root = ET.Element("report")
        nmap_log_element = ET.SubElement(root, "nmap_log")
        with open(self.nmap_log, 'r') as nmap_file:
            nmap_log_element.text = "\n".join(nmap_file.readlines())
        total_urls = ET.SubElement(root, "total_urls_visited")
        total_urls.text = str(self.extract_number_of_visited_urls())
        for log_file, vulnerabilities in vulns_dict.items():
            log_element = ET.SubElement(root, "log")
            log_element.set("name", log_file)
            num_vulnerabilities = ET.SubElement(log_element, "num_vulnerabilities")
            num_vulnerabilities.text = str(len(vulnerabilities))
            if vulnerabilities:
                # Add description element before iterating over vulnerabilities
                description = ET.SubElement(log_element, "description")
                description.text = self.get_vulnerability_description(vulnerabilities[0]['name'])
                for entry in vulnerabilities:
                    vuln = ET.SubElement(log_element, "vulnerability")
                    name = ET.SubElement(vuln, "name")
                    name.text = entry['name']
                    url = ET.SubElement(vuln, "url")
                    url.text = entry['url']
                    payload = ET.SubElement(vuln, "payload")
                    payload.text = entry['payload']
                # Add remediation steps element after iterating over vulnerabilities
                remediation_steps = ET.SubElement(log_element, "remediation_steps")
                remediation_steps.text = self.get_remediation_steps(vulnerabilities[0]['name'])
                if self.include_cyber_threat_intelligence:
                    keyword = vulnerabilities[0]['name']
                    cves = self.nvd.search_cve(keyword)
                    cwe_id=None
                    if cves:
                        cve_element = ET.SubElement(log_element, "recent_cves")
                        for cve in cves:
                            cve_id = ET.SubElement(cve_element, "cve_id")
                            cve_id.text = cve.id
                            for description in cve.descriptions:
                                if description.lang == 'en':
                                    description_element = ET.SubElement(cve_element, "description")
                                    description_element.text = description.value
                        for cwe in cve.cwe:
                            if cwe.lang == 'en':
                                cwe_id = cwe.value.replace('CWE-', '')
                                cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                                cwe_element = ET.SubElement(cve_element, "cwe")
                                cwe_element.text = cwe_url
                    else:
                        no_cve_element = ET.SubElement(log_element, "no_cves")
                        no_cve_element.text = f"No {log_file} CVE's in the last 4 months"

                # Ensure self.report_file is properly set to a file path
                # Open the file in write mode before writing to it
        with open(self.report_file, "wb") as f:
                tree = ET.ElementTree(root)
                tree.write(f, encoding="utf-8", xml_declaration=True)

    def write_json_output(self, vulns_dict):
        json_data = {
            "total_urls_visited": self.extract_number_of_visited_urls(),
            "vulnerabilities": []
        }
        with open(self.nmap_log, 'r') as nmap_file:
            json_data["nmap_log"] = nmap_file.read()
        for log_file, vulnerabilities in vulns_dict.items():
            description = None
            remediation_steps = None
            log_entry = {}
            if vulnerabilities:
                description = self.get_vulnerability_description(vulnerabilities[0]['name'])
                remediation_steps = self.get_remediation_steps(vulnerabilities[0]['name'])
                remediation_steps = remediation_steps.replace("\n", " ")
                log_entry = {
                    "Vulnerability": log_file,
                    "num_vulnerabilities": len(vulnerabilities),
                    "description": description,
                    "remediation steps": remediation_steps,
                    "vulnerabilities": []
                }
                for entry in vulnerabilities:
                    vuln_entry = {
                        "url": entry['url'],
                        "payload": entry['payload']
                    }
                    log_entry["vulnerabilities"].append(vuln_entry)
                if self.include_cyber_threat_intelligence:
                    keyword = vulnerabilities[0]['name']
                    cves = self.nvd.search_cve(keyword)
                    cve_list = []
                    if cves:
                        cve = None
                        for cve in cves:
                            cve_data = {
                                "cve_id": cve.id,
                                "descriptions": [description.value for description in cve.descriptions if
                                                 description.lang == 'en']
                            }
                            cve_list.append(cve_data)
                        log_entry["recent_cves"] = cve_list
                        # Adding CWE link
                        cwe_id = cve.cwe[0].value.replace('CWE-', '') if cve.cwe else None
                        cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id else None
                        if cwe_url:
                            log_entry["cwe_link"] = cwe_url
                    else:
                        log_entry["no_cves"] = f"No {log_file} CVE's in the last 4 months"
            else:
                log_entry = {
                    "Vulnerability": log_file,
                    "num_vulnerabilities": len(vulnerabilities)
                }
            json_data["vulnerabilities"].append(log_entry)
        with open(self.report_file, 'w') as f:
            json.dump(json_data, f, indent=4, ensure_ascii=False)


    def get_vulnerability_description(self, vulnerability_name):
        cleaned_name = vulnerability_name.lower().replace(" vulnerability", "")
        # Define vulnerability descriptions for each vulnerability name
        if cleaned_name == "sql injection":
            return "SQL injection is a code injection technique that attackers use to manipulate databases. It allows attackers to execute malicious SQL statements that can extract sensitive data or modify database contents."
        elif cleaned_name == "command injection":
            return "Command injection is an attack in which an attacker can execute arbitrary commands on the server. This can lead to unauthorized access, data leakage, and system compromise."
        elif cleaned_name == "reflected cross site scripting":
            return "Reflected Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into a web application, which are then reflected back to the user's browser. This can lead to client-side code execution and various security risks."
        elif cleaned_name == "stored cross site scripting":
            return "Stored Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into a web application, which are then stored and executed when other users access the affected pages. This can lead to client-side code execution and various security risks."
        elif cleaned_name == "remote file inclusion":
            return "Remote file inclusion (RFI) is an attack that allows an attacker to include remote files on a website. This can lead to the execution of arbitrary code and unauthorized access to server resources."
        elif cleaned_name == "local file inclusion":
            return "Local file inclusion (LFI) is a type of vulnerability that allows an attacker to include files on a server through the web browser. This can lead to information disclosure and remote code execution."
        elif cleaned_name == "verb tampering":
            return "Verb tampering is a type of attack that involves modifying HTTP request methods (verbs) to bypass security controls or access unauthorized resources."
        elif cleaned_name == "xml external entity injection":
            return "XML External Entity (XXE) injection is a vulnerability that allows an attacker to exploit poorly configured XML parsers. It can lead to sensitive data disclosure and server-side request forgery (SSRF)."
        elif cleaned_name == "server side template injection":
            return "Server-side template injection (SSTI) is a vulnerability that allows an attacker to inject malicious code into server-side templates. This can lead to remote code execution and server compromise."
        else:
            return "No description available"

    def get_remediation_steps(self, vulnerability_name):
        cleaned_name = vulnerability_name.lower().replace(" vulnerability", "")
        # Define remediation steps for each vulnerability name
        if cleaned_name == ("SQL Injection".lower()):
            return "1. Use parameterized queries or prepared statements to prevent SQL injection attacks.\n2. Validate and sanitize user input to prevent malicious input from reaching the database."
        elif cleaned_name == ("Command Injection".lower()):
            return "1. Use whitelisting to restrict the set of allowed commands and parameters.\n2. Implement proper input validation and sanitization to prevent command injection vulnerabilities."
        elif cleaned_name == "reflected cross site scripting":
            return "1. Encode user input to prevent malicious scripts from executing.\n2. Implement Content Security Policy (CSP) headers to restrict the sources of executable scripts."
        elif cleaned_name == "stored cross site scripting":
            return "1. Validate and sanitize user input to prevent the storage of malicious scripts in the application.\n2. Implement proper output encoding when displaying user-generated content to mitigate XSS vulnerabilities."
        elif cleaned_name == ("Remote File Inclusion".lower()):
            return "1. Avoid dynamically including remote files in web applications.\n2. Use allow list-based input validation to restrict the inclusion of files."
        elif cleaned_name == ("Local File Inclusion".lower()):
            return "1. Avoid passing user-controlled input directly to file inclusion functions.\n2. Implement proper input validation and sanitize file paths to prevent LFI vulnerabilities."
        elif cleaned_name == ("Verb Tampering".lower()):
            return "1. Use secure HTTP methods (e.g., GET, POST) and avoid using less common methods.\n2. Implement access controls and proper authorization mechanisms to restrict access to sensitive resources."
        elif cleaned_name == ("XML External Entity Injection".lower()):
            return "1. Disable external entity processing in XML parsers.\n2. Use XML libraries and parsers that mitigate XXE vulnerabilities by default."
        elif cleaned_name == ("Server Side Template Injection".lower()):
            return "1. Avoid passing user-controlled data directly into server-side templates.\n2. Implement template sandboxing and secure templating engines to mitigate SSTI vulnerabilities."
        else:
            return "No remediation available"