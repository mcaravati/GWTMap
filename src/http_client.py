import logging
from getpass import getpass

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from code import classify_code, Code

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger(__name__)


class HttpClient:
    def __init__(self, args, base_url: str):
        if args.proxy is not None:
            self._proxies = {args.proxy.split(":")[0].lower(): args.proxy}
        else:
            self._proxies = None

        if args.cookies is not None:
            cookies_list = {}
            for cookie in args.cookies.split(";"):
                cookies_list[cookie.split("=")[0].strip()] = cookie.split("=")[1].strip()
            self._cookies = cookies_list
        else:
            self._cookies = None

        if args.basic:
            print("HTTP Basic Auth")
            http_user = input("Username: ")
            http_pass = getpass("Password: ")
            self._auth = HTTPBasicAuth(http_user, http_pass)
        else:
            self._auth = None

        self._base_url = '/'.join((base_url.split('/')[:-1])) + '/'
        self._permutation = ""

    def get(self, url: str) -> Code:
        response = requests.get(url, proxies=self._proxies, cookies=self._cookies, auth=self._auth, verify=False)

        if response.status_code != 200:
            raise Exception("Request failed: {}".format(response.text))

        file_name = url.split('/')[-1]
        return classify_code(file_name, response.text)

    def set_permutation(self, permutation: str):
        self._permutation = permutation

    def send_rpc_probe(self, url, data) -> None:
        headers = {
            "Content-Type": "text/x-gwt-rpc; charset=utf-8",
            "X-GWT-Permutation": self._permutation,
            "X-GWT-Module-Base": self._base_url,
        }

        try:
            response = requests.post(
                url, data=data.replace("§", ""),
                headers=headers, proxies=self._proxies, cookies=self._cookies, auth=self._auth, verify=False
            )
            logger.info(f"HTTP/1.1 {response.status_code}: {response.text}")
        except requests.exceptions.RequestException:
            logging.error(f"Probe failed for {url}")
