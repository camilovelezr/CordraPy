"""Cordra Response Functions and Classes."""
import requests
import logging
from functools import singledispatchmethod
from dataclasses import dataclass, field
from requests.models import Response
from cordrapy.session import CordraConnection

from typing import Any, Union, Optional

logger = logging.getLogger("CordraPy")


@dataclass
class CordraHandle:
    """Handle (id) for Cordra Objects."""

    value: str
    connection: CordraConnection = field(repr=False)

    def __post__init__(self):
        prefix = self.value.split("/")[0]
        if prefix.startswith('"'):
            assert (
                prefix[1 : len(prefix)] == self.connection.prefix
            ), "prefix does not match connection's prefix"
        else:
            assert (
                prefix == self.connection.prefix
            ), "prefix does not match connection's prefix"


class CordraResponse:
    """Object for Cordra Response."""

    def __init__(self, response: Response):
        if str(response.status_code)[0] != "2":  # change to if not 200
            if not response.content == b"":  # TODO check
                logger.error(response.text)
            response.raise_for_status()
        self.status = response.status_code
        self.body = response.content
        self.json = response.json()  # make this a @property


class CordraObject:
    """Object for Cordra Object."""

    # @singledispatchmethod
    # def __init__(self, response: CordraResponse, c_c: CordraConnection):
    #     self.response = response.json
    #     self.handle = CordraHandle(response.json["id"], c_c)

    # @__init__.register
    # def _(
    #     self, response: dict, handle: str, c_c: CordraConnection
    # ):  # TODO check if bytes possible
    #     h = CordraHandle(handle, c_c)
    #     self.handle = h
    #     self.response = response
    def __init__(
        self,
        response: Union[CordraResponse, dict],
        c_c: CordraConnection,
        handle: Optional[Union[str, CordraHandle]] = None,
    ):  # TODO check if bytes possible
        if isinstance(response, CordraResponse):
            response = response.json
        self.response = response
        if isinstance(handle, str):
            handle = CordraHandle(handle, c_c)
        if not handle:
            handle = CordraHandle(self.response["id"], c_c)
        self.handle = handle

        # TODO work on document jl docs vs py, including sven's
        # google doc


# auth_json = {
#     "grant_type": "password",
#     "username": "admin",
#     "password": "pro03",
# }
cc = CordraConnection("https://localhost", "admin", verify=False)
r = requests.get(
    cc.host + "/objects/test/hello",
    verify=False,
    # headers=cc.auth.update({"Content-Type": "application/json"}),
    headers=cc.auth,
    params={"full": True},
)
c = CordraResponse(r)
co = CordraObject(c, cc)
co2 = CordraObject(c.json, cc, "test/hello")
s = 2


# class CordraObject:
#     # response: dict[str, Any] = field(init=False)
#     # handle: CordraHandle = field(init=False)

#     @singledispatchmethod
#     def __init__(cls, response, **kwargs):
#         raise ValueError("invalid response type %s" % type(response))

#     @__init__.register
#     def _(cls, response: CordraResponse, cc: CordraConnection):
#         body =


# def __init__(self,
#              response: dict[str, Any],
#              handle: CordraHandle
#              ):
#              # TODO finish this, look at multidispatch
