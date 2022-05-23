from models.qualys import Qualys
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.menu import Menu
from models.file_manager import FileManager
from views.viewer import Viewer
import xml.etree.ElementTree as ElT
from datetime import date
import os


class Controller:

    def __init__(self):
        self.qualys = Qualys()
        self.viewer = Viewer()
        self.file_manager = FileManager()

    def handle_vm_detections(self, query_payload):
        detection_response = self.qualys.get_vm_detections(query_payload)
        root = self.handle_xml_data(detection_response)
        assets = []
        qids = []
        for host_vuln in root.findall('.//HOST'):
            asset = Asset(hostname=host_vuln.find('.//HOSTNAME').text, ip=host_vuln.find('.//IP').text)
            for vuln in host_vuln.findall('.//DETECTION_LIST/DETECTION'):
                first_detected = vuln.find('.//FIRST_FOUND_DATETIME').text.replace("T", " ").replace("Z", "")
                last_detected = vuln.find('.//LAST_FOUND_DATETIME').text.replace("T", " ").replace("Z", "")
                vulnerability = Vulnerability(qid=vuln.find('.//QID').text, severity=vuln.find('.//SEVERITY').text,
                                              status=vuln.find('.//STATUS').text, first_detected=first_detected,
                                              last_detected=last_detected, is_ignored=vuln.find('.//IS_IGNORED').text)
                if vulnerability.qid not in qids:
                    qids.append(vulnerability.qid)
                asset.vulnerabilities.append(vulnerability)
            if asset.hostname not in list(map(lambda asset_obj: asset_obj.hostname, assets)):
                assets.append(asset)
        response = self.qualys.get_vuln_title_by_qid(qids)
        qid_titles = self.get_qid_titles_from_xml(response)
        self.attrib_title_to_host_vulnerabilities(qid_titles, assets)
        return assets

    @staticmethod
    def handle_xml_data(request_response):
        chunk_size = 20*1024
        xml_data = ""
        for chunk in request_response.iter_content(chunk_size):
            chunk_str = chunk.decode("utf-8")
            xml_data += chunk_str
        root = ElT.fromstring(xml_data)
        return root

    def get_qid_titles_from_xml(self, query_response):
        titles = {}
        root = self.handle_xml_data(query_response)
        for vuln in root.findall('.//VULN_LIST/VULN'):
            vuln_qid = vuln.find('.//QID').text
            vuln_title = vuln.find('.//TITLE').text
            titles[vuln_qid] = vuln_title
        return titles

    @staticmethod
    def attrib_title_to_host_vulnerabilities(titles, hosts):
        for host in hosts:
            for vulnerability in host.vulnerabilities:
                vulnerability.title = titles[vulnerability.qid]

    @staticmethod
    def filter_date(data, payload):
        period = "_".join(payload.split("_")[-2::])
        operator = payload.split("_")[-3]
        date_today = date.today()
        assets = []
        helper_dict = {
            "last": "<=",
            "more": ">=",
            "7_days": "7",
            "30_days": "30"
        }
        for asset in data:
            vulns = []
            for vuln in asset.vulnerabilities:
                first_detect = list(map(lambda x: int(x), vuln.first_detected.split(" ")[0].split("-")))
                first_detect = date(first_detect[0], first_detect[1], first_detect[2])
                delta = date_today - first_detect
                if eval(str(delta.days)+helper_dict[operator]+helper_dict[period]):
                    vulns.append(vuln)
            asset.vulnerabilities = vulns
            if asset.hostname not in list(map(lambda asset_obj: asset_obj.hostname, assets)) and asset.vulnerabilities:
                assets.append(asset)
        return assets

    def save_data(self, data, tag):
        self.viewer.show_file_manager_cache(self.file_manager.cache)
        files_folder = "files"
        save_data_menu = Menu(self, "SAVE DATA", ["Yes, save on file", "No, but store on cache", "No, discard output"])
        save_data_choice = save_data_menu.open()
        if save_data_choice == len(save_data_menu.options):
            return
        if save_data_choice == 2:
            self.file_manager.add_to_cache(tag, data)
            print(f"[ + ] Data added to cache!")
        if save_data_choice == 3:
            return
        if save_data_choice == 1:
            self.file_manager.add_to_cache(tag, data)
            if not os.path.exists(files_folder):
                os.makedirs(files_folder)
            self.file_manager.workbook_name = input("---> File name: ")
            if not self.file_manager.workbook_name.endswith(".xlsx"):
                self.file_manager.workbook_name += ".xlsx"
            self.file_manager.save_workbook(f"{files_folder}/{self.file_manager.workbook_name}")
            print(f"[ + ] Saved as '{files_folder}/{self.file_manager.workbook_name}'.\n")
