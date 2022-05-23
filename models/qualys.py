import base64
import requests


class Qualys:

    USER_NAME = "cnduc3cn"
    USER_PASS = "vNoU5fS$"

    def __init__(self):
        self.auth_credentials = base64.b64encode(f"{self.USER_NAME}:{self.USER_PASS}".encode()).decode()
        self.vm_api_endpoint = "https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/host/vm/detection/"
        self.knowledge_base_api_endpoint = "https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/"

    def __make_post_request(self, payload, endpoint):
        request_headers = {
            "X-Requested-With": "QualysPostman",
            "Authorization": "Basic " + self.auth_credentials
        }
        response = requests.request("POST", endpoint, headers=request_headers, data=payload)
        return response

    def get_vuln_title_by_qid(self, qids):
        """
        Creates a dictionary where the keys are the QIDs and de values are the QIDs vulnerability titles.

        Args:
            qids (`list` of str): list containing the QIDs to get the title

        Returns:
             titles (`dict` of str): dictionary in the format {"qid": "title"}

        """
        payload = {
            'action': 'list',
            'show_disabled_flag': '1',
            'details': 'All',
            'ids': ",".join(qids) if len(qids) > 1 else qids,
            'show_qid_change_log': '1',
            'show_supported_modules_info': '1',
            'show_pci_reasons': '1'
        }
        response = self.__make_post_request(payload, self.knowledge_base_api_endpoint)
        return response

    def get_vm_detections(self, query_payload):
        response = self.__make_post_request(query_payload, self.vm_api_endpoint)
        return response
