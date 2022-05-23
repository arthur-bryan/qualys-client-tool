class Viewer:

    def __init__(self):
        self.line_width = 225

    def show_detections(self, detections):
        num_assets = num_vulns = 0
        vulns = []
        print("*" * self.line_width)
        print(f"{'QID'.ljust(8, ' ')}{'SEVERITY'.ljust(12, ' ')}{'ASSET HOSTNAME'.ljust(22, ' ')}"
              f"{'ASSET IP'.ljust(18, ' ')}{'STATUS'.ljust(12, ' ')}{'TITLE'.ljust(105, ' ')}"
              f"{'FIRST DETECTED'.ljust(25, ' ')}{'LAST DETECTED'.ljust(25, ' ')}")
        print("*" * self.line_width)
        for asset in detections:
            num_assets += 1
            for vuln in asset.vulnerabilities:
                if vuln.title not in vulns:
                    vulns.append(vuln.title)
                num_vulns += 1
                print(f"{vuln.qid.ljust(8, ' ')}{vuln.severity.ljust(12, ' ')}{asset.hostname.ljust(22, ' ')}"
                      f"{asset.ip.ljust(18, ' ')}{vuln.status.ljust(12, ' ')}{vuln.title.ljust(105, ' ')}"
                      f"{vuln.first_detected.ljust(25, ' ')}{vuln.last_detected.ljust(25, ' ')}")
        print("*" * self.line_width)
        print(f"Total detections: {num_vulns}\nTotal assets: {num_assets}\nDifferent vulnerabilities: {len(vulns)}\n")
        del vulns, num_vulns, num_assets

    @staticmethod
    def show_menu_options(title, options):
        options.append("Back")
        print(f"\n[ {title} ] Choose an option:")
        for num, option in enumerate(options):
            print(f"[ {num + 1} ] {option}")

    @staticmethod
    def show_file_manager_cache(cache):
        print("[ CACHE ] Files currently on cache:")
        for sheet in cache:
            print(list(sheet.keys())[0])
