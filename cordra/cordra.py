import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# global variables
_OBJECTS_ENDPOINT = 'objects/'
_ACL_ENDPOINT = 'acls/'
_TOKEN_CREATE_ENDPOINT = 'auth/token'
_TOKEN_READ_ENDPOINT = 'auth/introspect'
_TOKEN_DELETE_ENDPOINT = 'auth/revoke'
_TOKEN_GRANT_TYPE = 'password'
_TOKEN_TYPE = 'Bearer'


def _endpoint_url(host, endpoint):
    return host.strip('/') + '/' + endpoint


def _check_response(response):
    if not response.ok:
        if len(response.content) > 0:
            print('CordraPy Error Message: ' + response.json()['message'])
        response.raise_for_status()

    return response.content


def _set_auth(username, password):
    if username and password:
        auth = requests.auth.HTTPBasicAuth(username, password)
    else:
        auth = None
    return auth


def _get_token_value(token):
    if isinstance(token, str):
        return token
    elif isinstance(token, dict):
        try:
            return token['access_token']
        except BaseException as e:
            raise Exception('Token json format error.') from e
    else:
        raise Exception('Token format error.')


def _set_headers(token):
    if token:
        headers = {}
        headers['Authorization'] = _TOKEN_TYPE + ' ' + _get_token_value(token)
    else:
        headers = None
    return headers


class CordraObject:
    """Class that contains methods to operate with digital objects in Cordra."""

    @classmethod
    def create(cls,
               host,
               obj_json,
               obj_type,
               handle=None,
               suffix=None,
               dry_run=False,
               username=None,
               password=None,
               token=None,
               verify=None,
               full=False,
               payloads=None,
               acls=None):
        """Creates a new digital object in Cordra.

        Creates a digital object from a JSON representation of it.
        Objects can include payloads.

        Args:
            host:
                The address of the instance of Cordra.
                Usually https://localhost:8443.
            obj_json (dict): Object to be uploaded.
            obj_type: Object's Type in Cordra.
            handle: (optional) Cordra object's handle (includes prefix).
            suffix: (optional) Cordra's object suffix.
            dryRun (bool):
                If True: run but don't actually add the item.
                Default is False.

            username: Cordra's username.
            password: Cordra's password.
            token (cordra.Token):
                Cordra's authentication token.
                If provided, no username and no password needed.
            verify (bool): SSL verification.
            full (bool): Return meta-data in addition to object data.
            acls (dict):
                Access control lists. Syntax: {"readers":[], "writers":[]}.
                For example:
                acls={"readers":["public"], "writers":["public"]}.
            payloads (dict):
                Payload data (like binary or file data) to upload with object.
                Syntax: {"FileDescription": ("file_name", file object)}.
                Note that the file object must be read in binary mode.
                For example:
                
                with open("picture.png", "rb") as file:
                    my_payloads = {"My first payload" : ("picture.png", file)}
                    CordraObject.create(..., payloads=my_payloads)
                

        Returns:
            A dictionary that is the JSON representation of Cordra's response.

        """

        params = {}
        params['type'] = obj_type
        if handle:
            params['handle'] = handle
        if suffix:
            params['suffix'] = suffix
        if dry_run:
            params['dryRun'] = dry_run
        if full:
            params['full'] = full

        if payloads:  # multi-part request
            data = {}
            data['content'] = json.dumps(obj_json)
            if acls:
                data['acl'] = json.dumps(acls)
            r = _check_response(
                requests.post(_endpoint_url(host, _OBJECTS_ENDPOINT),
                              params=params,
                              files=payloads,
                              data=data,
                              auth=_set_auth(username, password),
                              headers=_set_headers(token),
                              verify=verify))
            return json.loads(r)
        else:  # simple request
            if acls:
                params['full'] = True
            obj_r = _check_response(
                requests.post(_endpoint_url(host, _OBJECTS_ENDPOINT),
                              params=params,
                              data=json.dumps(obj_json),
                              auth=_set_auth(username, password),
                              headers=_set_headers(token),
                              verify=verify))

            if acls and not dry_run:
                obj_id = obj_r['id']
                acl_r = _check_response(
                    requests.put(_endpoint_url(host, _ACL_ENDPOINT) + obj_id,
                                 params=params,
                                 data=json.dumps(acls),
                                 auth=_set_auth(username, password),
                                 headers=_set_headers(token),
                                 verify=verify))
                return [json.loads(obj_r), json.loads(acl_r)]
            else:
                return json.loads(obj_r)

    @classmethod
    def read(cls,
             host,
             obj_id,
             username=None,
             password=None,
             token=None,
             verify=None,
             json_pointer=None,
             json_filter=None,
             full=False):
        """Retrieve a Cordra object JSON by identifer."""

        params = {}
        params['full'] = full
        if json_pointer:
            params['jsonPointer'] = json_pointer
        if json_filter:
            params['filter'] = str(json_filter)
        r = _check_response(
            requests.get(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                         params=params,
                         auth=_set_auth(username, password),
                         headers=_set_headers(token),
                         verify=verify))
        return json.loads(r)

    @classmethod
    def read_payload_info(cls,
                          host,
                          obj_id,
                          username=None,
                          password=None,
                          token=None,
                          verify=None):
        '''Retrieve a Cordra object payload names by identifer.'''

        params = {}
        params['full'] = True
        r = _check_response(
            requests.get(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                         params=params,
                         auth=_set_auth(username, password),
                         headers=_set_headers(token),
                         verify=verify))
        return json.loads(r)['payloads']

    @classmethod
    def read_payload(cls,
                     host,
                     obj_id,
                     payload,
                     username=None,
                     password=None,
                     token=None,
                     verify=None):
        '''Retrieve a Cordra object payload by identifer and payload name.'''

        params = {}
        params['payload'] = payload
        r = _check_response(
            requests.get(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                         params=params,
                         auth=_set_auth(username, password),
                         headers=_set_headers(token),
                         verify=verify))
        return r

    @classmethod
    def update(cls,
               host,
               obj_id,
               obj_json=None,
               json_pointer=None,
               obj_type=None,
               dry_run=False,
               username=None,
               password=None,
               token=None,
               verify=None,
               full=False,
               payloads=None,
               payload_to_delete=None,
               acls=None):
        '''Update a Cordra object'''

        params = {}
        if obj_type:
            params['type'] = obj_type
        if dry_run:
            params['dryRun'] = dry_run
        if full:
            params['full'] = full
        if json_pointer:
            params['jsonPointer'] = json_pointer
        if payload_to_delete:
            params['payloadToDelete'] = payload_to_delete

        if payloads:  # multi-part request
            if not obj_json:
                raise Exception('obj_json is required when updating payload')
            data = {}
            data['content'] = json.dumps(obj_json)
            data['acl'] = json.dumps(acls)
            r = _check_response(
                requests.put(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                             params=params,
                             files=payloads,
                             data=data,
                             auth=_set_auth(username, password),
                             headers=_set_headers(token),
                             verify=verify))
            return r
        elif acls:  # just update ACLs
            r = _check_response(
                requests.put(_endpoint_url(host, _ACL_ENDPOINT) + obj_id,
                             params=params,
                             data=json.dumps(acls),
                             auth=_set_auth(username, password),
                             headers=_set_headers(token),
                             verify=verify))
            return r
        else:  # just update object
            if not obj_json:
                raise Exception('obj_json is required')
            r = _check_response(
                requests.put(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                             params=params,
                             data=json.dumps(obj_json),
                             auth=_set_auth(username, password),
                             headers=_set_headers(token),
                             verify=verify))
            return r

    @classmethod
    def delete(cls,
               host,
               obj_id,
               json_pointer=None,
               username=None,
               password=None,
               token=None,
               verify=None):
        '''Delete a Cordra object'''

        params = {}
        if json_pointer:
            params['jsonPointer'] = json_pointer

        r = _check_response(
            requests.delete(_endpoint_url(host, _OBJECTS_ENDPOINT) + obj_id,
                            params=params,
                            auth=_set_auth(username, password),
                            headers=_set_headers(token),
                            verify=verify))
        return r

    @classmethod
    def find(cls,
             host,
             query,
             username=None,
             password=None,
             token=None,
             verify=None,
             ids=False,
             json_filter=None,
             full=False):
        '''Find a Cordra object by query'''

        params = {}
        params['query'] = query
        params['full'] = full
        if json_filter:
            params['filter'] = str(json_filter)
        if ids:
            params['ids'] = True
        r = _check_response(
            requests.get(_endpoint_url(host, _OBJECTS_ENDPOINT),
                         params=params,
                         auth=_set_auth(username, password),
                         headers=_set_headers(token),
                         verify=verify))
        return r


class Token:
    """Cordra's Authorization token."""

    @classmethod
    def create(cls, host, username, password, verify=None, full=False):

        params = {}
        params['full'] = full

        auth_json = {}
        auth_json['grant_type'] = _TOKEN_GRANT_TYPE
        auth_json['username'] = username
        auth_json['password'] = password

        r = _check_response(
            requests.post(_endpoint_url(host, _TOKEN_CREATE_ENDPOINT),
                          params=params,
                          data=auth_json,
                          verify=verify))
        return json.loads(r)

    @classmethod
    def read(cls, host, token, verify=None, full=False):
        '''Read an access Token'''

        params = {}
        params['full'] = full

        auth_json = {}
        auth_json['token'] = _get_token_value(token)

        r = _check_response(
            requests.post(_endpoint_url(host, _TOKEN_READ_ENDPOINT),
                          params=params,
                          data=auth_json,
                          verify=verify))
        return json.loads(r)

    @classmethod
    def delete(cls, host, token, verify=None):
        '''Delete an access Token'''

        auth_json = {}
        auth_json['token'] = _get_token_value(token)

        r = _check_response(
            requests.post(_endpoint_url(host, _TOKEN_DELETE_ENDPOINT),
                          data=auth_json,
                          verify=verify))
        return json.loads(r)
