"""REST Session."""

import requests
from typing import Optional, Union
from getpass import getpass


class CordraConnection:
    def __init__(
        self,
        host: str,
        username: Optional[str] = None,
        prefix: Optional[str] = None,
        verify: bool = True,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.verify = verify
        # _usernames: dict[str, str],  # for use in acls
        # _ids: dict[str, str],  # for use in acls
        if self.username:
            password = getpass()
            auth_json = {
                "grant_type": "password",
                "username": self.username,
                "password": password,
            }
            r = requests.post(
                f"{self.host}/auth/token", data=auth_json, verify=self.verify
            )
            self._token = r.json()["access_token"]

        # test only requests, requests sessions inside jupyter notebook
        if not prefix:
            # get prefix
            r = requests.get(f"{self.host}/design", verify=self.verify)
            self.prefix = r.json()["handleMintingConfig"]["prefix"]

        self._r = r

    @property
    def auth(self):
        """Auth for HTTP requests."""
        return {"Authorization": f"Bearer {self._token}"}


# c = CordraConnection("https://localhost", "admin", verify=False)

# TODO functions to do with CordraConnection() as ..
# s = 2
