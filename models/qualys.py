import base64
import requests


class Qualys:
    """
    Class that represents the Qualys client.

    Attributes:
        user_name (str): username used to consume Qualys API.
        user_pass (str): password used by user to login.
        auth_credentials (str): base64 formated user+password used to consume Qualys API.
        vm_api_endpoint (str): URL for Qualys VM/PC module API.
        knowledge_base_api_endpoint (str): URL for Qualys the knowledge base API.
    """

    def __init__(self, username: str, password: str):
        """
        Constructor method of class Qualys.

        Args:
            username: username used to consume Qualys API.
            password: password used by user to login.
        """
        self.user_name = username
        self.user_pass = password
        self.auth_credentials = base64.b64encode(f"{self.user_name}:{self.user_pass}".encode()).decode()
        self.vm_api_endpoint = "https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/host/vm/detection/"
        self.knowledge_base_api_endpoint = "https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/"

    def __make_post_request(self, payload: dict, endpoint: str) -> requests.Response:
        """
        Makes a POST request to the API endpoint, passing the payload as parameter, then return the response.

        Args:
            payload: dict containing the query data used to make the request.
            endpoint: the API URL that will receive de request.

        Returns:
             response: request response XML data.
        """
        request_headers = {
            "X-Requested-With": "QualysPostman",
            "Authorization": "Basic " + self.auth_credentials
        }
        response = requests.request("POST", endpoint, headers=request_headers, data=payload)
        return response

    def get_vuln_info_by_qid(self, qids: list) -> requests.Response:
        """
        Consume the API to get information about vulnerabilities using its QIDs.

        Args:
            qids: list containing the QIDs to get the info.

        Returns:
             response: request response XML data.
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

    def get_vm_detections(self, query_payload: dict) -> requests.Response:
        """
        Consume the API to get vulnerability detections based on specifc queries.

        Args:
            query_payload: dictionary containing the data to use on the detection query.

        Returns:
             response: request response XML data.
        """
        response = self.__make_post_request(query_payload, self.vm_api_endpoint)
        return response
