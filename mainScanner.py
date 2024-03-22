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
              "using the following parameters")
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

    #def stop_scan(self):
    #    sys.exit("Scan stopped")
