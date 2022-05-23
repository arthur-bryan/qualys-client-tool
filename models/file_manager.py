from openpyxl import Workbook


class FileManager:

    def __init__(self):
        self.cache = []
        self.workbook = Workbook()
        self.workbook_name = ""

    def add_to_cache(self, tag, data):
        self.cache.append({tag: data})

    def get_data_on_cache(self):
        print(len(self.workbook.worksheets))
        return self.cache

    def save_workbook(self, filename):
        if "Sheet" in self.workbook.sheetnames:
            del self.workbook["Sheet"]
        header = ["QID", "SEVERITY", "HOSTNAME", "IP ADDRESS", "STATUS", "TITLE", "FIRST DETECTED", "LAST DETECTED"]
        for index, data in enumerate(self.cache):
            self.workbook.create_sheet(title=list(data.keys())[0])
            sheet = self.workbook.worksheets[index]
            sheet.append(header)
            for asset in list(data.values())[0]:
                for vuln in asset.vulnerabilities:
                    sheet.append([vuln.qid, vuln.severity, asset.hostname, asset.ip, vuln.status,
                                 vuln.title, vuln.first_detected, vuln.last_detected])
        self.workbook.save(filename)
