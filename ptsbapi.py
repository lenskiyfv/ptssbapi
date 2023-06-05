import requests
import urllib3

from . import exceptions


class Client:
    def __init__(
        self,
        host: str,
        api_key: str,
        analysis_depth: int = 2,
        sandbox_enabled: bool = False,
        sandbox_image_id: str = None,
        sandbox_analysis_duration: int = None,
        verify: bool = False,
    ):
        self.host = host
        self.api_key = api_key
        self.analysis_depth = analysis_depth
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_image_id = sandbox_image_id
        self.sandbox_analysis_duration = sandbox_analysis_duration
        self.headers = {"x-api-key": self.api_key, "accept": "application/json"}
        self.root_url = f"https://{self.host}/api/v1"
        if not verify:
            self._disable_insecure_request_warning()
        self.verify = verify

    def send_request(
        self, relative_url: str, headers: dict, json: dict = None, data: bytes = None
    ) -> dict:
        url = self.root_url + relative_url

        response = requests.post(
            url=url, headers=headers, json=json, data=data, verify=self.verify
        )

        if response.ok:
            return response.json()

        if response.status_code == 400:
            raise exceptions.BadApiRequest(
                status_code=response.status_code, message=response.text
            )

        elif response.status_code == 401:
            raise exceptions.BadApiKey(
                status_code=response.status_code, message=response.text
            )

        elif response.status_code == 404:
            raise exceptions.ObjectNotFound(
                status_code=response.status_code, message=response.text
            )

        elif response.status_code == 405:
            raise exceptions.BadApiMethod(
                status_code=response.status_code, message=response.text
            )

        elif response.status_code >= 500:
            raise exceptions.InternalServerError(
                status_code=response.status_code, message=response.text
            )

    def check_health(self) -> dict:
        relative_url = "/maintenance/checkHealth"
        return self.send_request(relative_url=relative_url, headers=self.headers)

    def upload_scan_file(self, file_path: str) -> dict:
        relative_url = "/storage/uploadScanFile"
        headers = self.headers
        headers["content-type"] = "application/octet-stream"
        data = self._get_binary_file(file_path=file_path)
        return self.send_request(relative_url=relative_url, headers=headers, data=data)

    def create_scan_task(
        self, file_uri: str, file_name: str, passwords_for_unpack: list = []
    ) -> dict:
        relative_url = "/analysis/createScanTask"
        json = {
            "file_uri": file_uri,
            "file_name": file_name,
            "async_result": True,
            "short_result": True,
            "options": {
                "analysis_depth": self.analysis_depth,
                "passwords_for_unpack": passwords_for_unpack,
                "sandbox": {
                    "enabled": self.sandbox_enabled,
                    "skip_check_mime_type": True,
                    "image_id": self.sandbox_image_id,
                    "analysis_duration": self.sandbox_analysis_duration,
                },
            },
        }
        return self.send_request(
            relative_url=relative_url, headers=self.headers, json=json
        )

    def check_scan_task(self, scan_id: str) -> dict:
        relative_url = "/analysis/checkTask"
        json = {"scan_id": scan_id}
        return self.send_request(
            relative_url=relative_url, headers=self.headers, json=json
        )

    def check_scan_report(self, scan_id: str) -> dict:
        relative_url = "/analysis/report"
        json = {"scan_id": scan_id}
        return self.send_request(
            relative_url=relative_url, headers=self.headers, json=json
        )

    def get_images(self) -> dict:
        relative_url = "/engines/sandbox/getImages"
        return self.send_request(relative_url=relative_url, headers=self.headers)

    @staticmethod
    def _get_binary_file(file_path: str) -> bytes:
        with open(file=file_path, mode="rb") as f:
            return f.read()

    @staticmethod
    def _disable_insecure_request_warning() -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
