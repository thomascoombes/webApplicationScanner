import requests
import re
import time

from activeScanRules.activeScanner import ActiveScanner

def initialise_mysql_error_messages():
    mysql_error_messages = [
        re.compile("You have an error in your SQL syntax"),
        #re.compile("com.mysql.jdbc.exceptions"),
        #re.compile("org.gjt.mm.mysql"),
        #re.compile("ODBC driver does not support"),
        #re.compile("The used SELECT statements have a different number of columns"),
    ]
    return mysql_error_messages

def initialise_mssql_error_messages():
    mssql_error_messages = [
        re.compile("com.microsoft.sqlserver.jdbc"),
        re.compile("com.microsoft.jdbc"),
        re.compile("com.inet.tds"),
        re.compile("weblogic.jdbc.mssqlserver"),
        re.compile("\[Microsoft]"),
        re.compile("\[SQLServer]"),
        re.compile("\[SQLServer 2000 Driver for JDBC]"),
        re.compile("net.sourceforge.jtds.jdbc"),
        re.compile("80040e14"),
        re.compile("800a0bcd"),
        re.compile("80040e57"),
        re.compile("ODBC driver does not support"),
        re.compile("All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists"),
        re.compile("All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists"),
    ]
    return mssql_error_messages
def initialise_oracle_error_messages():
    oracle_error_messages = [
        re.compile("oracle.jdbc"),
        re.compile("SQLSTATE\[HY"),
        re.compile("ORA-00933"),
        re.compile("ORA-06512"),
        re.compile("SQL command not properly ended"),
        re.compile("ORA-00942"),
        re.compile("ORA-29257"),
        re.compile("ORA-00932"),
        re.compile("query block has incorrect number of result columns"),
        re.compile("ORA-01789")
    ]
    return oracle_error_messages

def initialise_postgre_error_messages():
    postgre_error_messages = [
        re.compile("org.postgresql.util.PSQLException"),
        re.compile("org.postgresql"),
        re.compile("each UNION query must have the same number of columns")
    ]
    return postgre_error_messages

def initialise_sybase_error_messages():
    sybase_error_messages = [
        re.compile("com.sybase.jdbc"),
        re.compile("com.sybase.jdbc2.jdbc"),
        re.compile("com.sybase.jdbc3.jdbc"),
        re.compile("net.sourceforge.jtds.jdbc")
    ]
    return sybase_error_messages

def initialise_sqlite_error_messages():
    sqlite_error_messages = [
        re.compile("near \".+\": syntax error"),
        re.compile("SQLITE_ERROR"),
        re.compile("SELECTs to the left and right of UNION do not have the same number of result columns")
    ]
    return sqlite_error_messages

def initialise_generic_sql_error_messages():
    generic_sql_error_messages = [
        re.compile("com.ibatis.common.jdbc"),
        re.compile("org.hibernate"),
        re.compile("sun.jdbc.odbc"),
        re.compile("\[ODBC Driver Manager]"),
        re.compile("ODBC driver does not support"),
        re.compile("System.Data.OleDb \(System.Data.OleDb.OleDbException\)"),
        re.compile("java.sql.SQLException \(in case more specific messages were not detected\)")
    ]
    return generic_sql_error_messages

def identify_dbms(response_text):
    dbms = ""
    # Check for MySQL error messages
    if any(msg.search(response_text) for msg in initialise_mysql_error_messages()):
        dbms = "MySQL"
    # Check for MS SQL Server error messages
    elif any(msg.search(response_text) for msg in initialise_mssql_error_messages()):
        dbms = "MS SQL Server"
    # Check for Oracle error messages
    elif any(msg.search(response_text) for msg in initialise_oracle_error_messages()):
        dbms = "Oracle"
    # Check for PostgreSQL error messages
    elif any(msg.search(response_text) for msg in initialise_postgre_error_messages()):
        dbms = "PostgreSQL"
    # Check for Sybase error messages
    elif any(msg.search(response_text) for msg in initialise_sybase_error_messages()):
        dbms = "Sybase"
    # Check for SQLite error messages
    elif any(msg.search(response_text) for msg in initialise_sqlite_error_messages()):
        dbms = "SQLite"
    # Check for generic SQL error messages
    elif any(msg.search(response_text) for msg in initialise_generic_sql_error_messages()):
        dbms = "Generic SQL"
    else:
        dbms = None
    return dbms

class ScanSQLInject(ActiveScanner):
    def __init__(self, visited_urls=None, log_file=None):
        super().__init__(visited_urls, log_file)

    def initialise_payloads(self):
        payloads =  "payloads/sqlInjectionPayloads/sqliInjectionPayloads.txt"
        payload_list = []
        with open(payloads, "r") as payload_file:
            for payload in payloads:
                payload_list.append(payload)
        payloads = [
            r"'"
            #r";",
            #r"-- ",
            #r"\"",
            #r")",
            #r"||",
            #r"&",
            #r"%20",
        ]
        return payloads

    def test_payloads(self, target_url, form_fields):
        # start_time = time.time()
        # Open the file containing SQL payloads
        payloads = self.initialise_payloads()
        # Initialise a flag to track if any potential vulnerability is found
        potential_vulnerability_found = False
        proxies = {'http': 'http://127.0.0.1:8080',
                   'https': 'http://127.0.0.1:8080'}  # for burp testing purposes
        form_method = form_fields[0][2].upper()

        for payload in payloads:
            self.logger.info(f"\tTesting payload: {payload} on {target_url}")
            # Prepare form data with SQL payload
            form_data = {}
            for field_tuple in form_fields:
                form_data[field_tuple[0]] = payload
            try:
                # Get the action URL or set it to the target URL if not found
                action = form_data.get('action', target_url)
                # Extract input fields from the form_data
                inputs = [key for key in form_data.keys() if key != 'method' and key != 'action' and key != 'page']
                # Prepare post data for submission
                post_data = {}
                for input_name in inputs:
                    post_data[input_name] = form_data[input_name]

                # Check if method is post or get
                response = None
                if form_method == 'POST':
                    response = requests.post(action, data=post_data)
                elif form_method == 'GET':
                    response = requests.get(action, params=post_data) #, proxies=proxies

                if self.check_response1(response, payload, target_url):
                    potential_vulnerability_found = True
                    break  # Break out of the loop if vulnerability found

            except Exception as e:
                self.logger.error(f"\tAn error occurred while sending form with SQL payload to {target_url}: {e}")

        # After testing all payloads, if no potential vulnerability is found, print the message
        if not potential_vulnerability_found:
            self.logger.info(f"\tNo SQL injection vulnerability found at: {target_url}")
            print(f"\033[32m[+] No SQL injection vulnerability found at: {target_url}\033[0m")

    def check_response(self, response, payload, url):
        # Check if response indicates successful injection
        if response.status_code == 200:
            dbms = identify_dbms(response.text)
            print(dbms)
            if dbms is None:
                return False
            else:
                self.logger.warning(f"SQL injection vulnerability found at: {url} with payload: {payload} for {dbms}")
                print(
                    f"\033[31m[+] SQL injection vulnerability found at: {url} with payload: {payload.strip()} for {dbms}\033[0m")
                return True
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")

    def check_response1(self, response, payload, url):
        # Check if response indicates successful injection
        patterns = initialise_mysql_error_messages()
        if response.status_code == 200:
            for pattern in patterns:
                match = pattern.search(response.text)
                if match:
                    matched_text = match.group()  # Get the matched text
                    self.logger.warning(
                        f"SQL injection vulnerability found at: {url} with payload: {payload} for MySQL")
                    print(
                        f"\033[31m[+] SQL injection vulnerability found at: {url} with payload: {payload.strip()} for MySQL\033[0m")
                    return True
            else:
                return False
        else:
            self.logger.error(f"\tUnexpected response code ({response.status_code}) for {url}")

