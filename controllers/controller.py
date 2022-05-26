import sys
import xml.etree.ElementTree
from models.qualys import Qualys
from models.asset import Asset
from models.vulnerability import Vulnerability
from models.menu import Menu
from models.file_manager import FileManager
from views.viewer import Viewer
import xml.etree.ElementTree as ElT
from datetime import date
import requests
import os


class Controller:
    """
    Class that represents the controller, that act as an interface between the models and views.

    Attributes:
        qualys (:obj:`Qualys`): model used to perform queries to Qualys API.
        viewer (:obj:`Viewer`): model used to format and show detection data in a proper way.
        file_manager: (:obj:`FileManager`): model used to store the detections outputs.
    """

    def __init__(self):
        """Contructor method of class Controller. This method initialize some models and views."""
        try:
            self.qualys = Qualys(os.environ["QUALYS_API_USER"], os.environ["QUALYS_API_PASSWORD"])
        except KeyError:
            print("[ - ] You must set environment variables: QUALYS_API_USER and QUALYS_API_PASSWORD\n")
            sys.exit(1)
        self.viewer = Viewer()
        self.file_manager = FileManager()

    def handle_vm_detections(self, query_payload):
        """Handles a request response containing XML data, returning it as an XML object.
         The request response is converted to string, then the string is converted to an XML element object.

        Args:
            query_payload: the request response XML data.

        Returns:
            root: an XML element easier to handle using xml.etree.ElementTree.
        """
        detection_response = self.qualys.get_vm_detections(query_payload)
        root = self.__handle_xml_data(detection_response)
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
        response = self.qualys.get_vuln_info_by_qid(qids)
        qid_titles = self.get_qid_titles_from_xml(response)
        self.attrib_title_to_host_vulnerabilities(qid_titles, assets)
        return assets

    @staticmethod
    def __handle_xml_data(request_response: requests.Response) -> xml.etree.ElementTree.Element:
        """Handles a request response containing XML data, returning it as an XML object.
         The request response is converted to string, then the string is converted to an XML element object.

        Args:
            request_response: the request response XML data.

        Returns:
            root: an XML element easier to handle using xml.etree.ElementTree.
        """
        chunk_size = 20*1024
        xml_data = ""
        for chunk in request_response.iter_content(chunk_size):
            chunk_str = chunk.decode("utf-8")
            xml_data += chunk_str
        root = ElT.fromstring(xml_data)
        return root

    def get_qid_titles_from_xml(self, query_response: requests.Response):
        """
        Searches for the QIDs and its titles from an XML string, then create a dict in the format: {"qid": "title"}.

        Args:
            query_response: request response XML data, containing QID info, result from Qualys KnowledgeBase.

        Returns:
            titles: dict contaning the QIDs and the correnspondig titles, eg: {"QID1000": "Example detection"}.
        """
        titles = {}
        root = self.__handle_xml_data(query_response)
        for vuln in root.findall('.//VULN_LIST/VULN'):
            vuln_qid = vuln.find('.//QID').text
            vuln_title = vuln.find('.//TITLE').text
            titles[vuln_qid] = vuln_title
        return titles

    @staticmethod
    def attrib_title_to_host_vulnerabilities(titles: dict, detections: list):
        """
        Assign the title to a vulnerability detection, based on its QID.

        Args:
            titles: dict contaning the QIDs and the correnspondig titles, eg: {"QID1000": "Example detection"}.
            detections: list containing Asset() objects, result from detections.

        """
        for asset in detections:
            for vulnerability in asset.vulnerabilities:
                vulnerability.title = titles[vulnerability.qid]

    @staticmethod
    def filter_period(data: list, payload_key: str) -> list:
        """Filter the detection results based on date periods.
        The filter is based on the payload key, that must be in the following patter: team_scope_operator_number_days.

        Args:
            data: list containing Asset() objects, result from detection.
            payload_key: name of the payload key, used to extract the period and operator to perform a filter.

        Returns:
            detections: list containing Asset() objects, result from the applied filter.
        """
        period = "_".join(payload_key.split("_")[-2::])
        operator = payload_key.split("_")[-3]
        date_today = date.today()
        detections = []
        helper_dict = {
            "last": "<",
            "more": ">=",
            "7_days": "7",
            "12_days": "12",
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
            if asset.hostname not in list(map(lambda asset_obj: asset_obj.hostname, detections)) \
                    and asset.vulnerabilities:
                detections.append(asset)
        return detections

    def save_data(self, data: list, tag: str):
        """Saves the cached data to an XLSX file.
        Each result from scan detection will be saved at a corresponding sheet.

        Args:
            data: list containing Asset() objects, result from detection.
            tag: title of the sheet for the corresponding data.
        """
        self.viewer.show_file_manager_cache(self.file_manager.cache)
        files_folder = "files"
        save_data_menu = Menu(self, "SAVE DATA", ["Yes, save on file", "No, but store on cache", "No, discard output"])
        save_data_choice = save_data_menu.open()
        if save_data_choice == len(save_data_menu.options):
            return
        if save_data_choice == 2:
            self.file_manager.add_to_cache(tag, data)
            print("[ + ] Data added to cache!")
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
