class Viewer:
    """
    Class that represents the Viewer, responsible to show the data in a proper way.

    Attributes:
        line_width (int): maximum size of the line when showing data.
    """
    def __init__(self):
        """Contructor method of class Viewer."""
        self.line_width = 225

    def show_detections(self, detections: list):
        """
        Show formated data from detections results.

        Args:
            detections: list containing the Asset objects, results from detections.
        """
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
    def show_menu_options(title: str, options: list):
        """
        Show formated menu options.

        Args:
            title: title of the menu.
            options: list containing menu options.
        """
        options.append("Back")
        print(f"\n[ {title} ] Choose an option:")
        for num, option in enumerate(options):
            print(f"[ {num + 1} ] {option}")

    @staticmethod
    def show_file_manager_cache(cache: list):
        """
        Show the sheet names stored on the cache of the file manager.

        Args:
            cache: list containing dicts with the detections tags and its contents, eg: [{"tag": [vuln1, vuln2]}].
        """
        print("[ CACHE ] Files currently on cache:")
        for sheet in cache:
            print(list(sheet.keys())[0])
