#!/usr/bin/env python
"""
Privat24 for Business CLI
"""

from urllib import request, parse as urlparse
import json
import os
import os.path
import sys
import argparse
from getpass import getpass
from configparser import ConfigParser
from datetime import datetime

class JSON(json.JSONEncoder):
    """
    JSON encoder capable of encoding datetime
    """
    @staticmethod
    def dumps(o):
        return json.dumps(o, cls=JSON, ensure_ascii=False)
    def default(self, o): # pylint: disable=E0202
        if isinstance(o, datetime):
            return o.isoformat()

        return super().default(o)

class Config(ConfigParser):
    """
    Handles CLI config file
    """
    PATH = os.path.expanduser("~/.config/p24.config")

    def write_config(self):
        """
        Writes config to file
        """
        with open(self.PATH, "w") as configfile:
            self.write(configfile)

    def read_config(self):
        """
        Reads config from file
        """
        self.read(self.PATH)

    def build_p24_client(self):
        """
        Builds privat24 client from config
        """
        self.read_config()
        creds = self["credentials"]
        return Privat24Business(creds["client_id"], creds["client_secret"],
                                creds["business_login"], creds["business_password"])

class HTTPCLient():
    """
    Thin wrapper over stdlib's urllib.request
    """
    JSON_HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    @staticmethod
    def get(url, params, headers={}.copy()):
        """
        Handles params
        """
        res = urlparse.urlparse(url)
        url_params = urlparse.parse_qs(res.query)
        url_params.update(params)

        new_query = urlparse.urlencode(url_params)
        new_url_obj = urlparse.ParseResult(
            res.scheme, res.netloc, res.path,
            res.params, new_query, res.fragment)
        new_url = urlparse.urlunparse(new_url_obj)

        req = request.Request(new_url, headers=headers, method="GET")
        return request.urlopen(req)

    def get_auth_json(self, url, token, params={}.copy(), headers={}.copy()):
        """
        Adds auth token and attempts to parse response body as json
        """
        headers = headers.copy()
        headers.update(self.JSON_HEADERS)
        headers["Authorization"] = f"Token {token}"

        response = self.get(url, params, headers)
        body = response.read()

        try:
            data = json.loads(body)
        except json.decoder.JSONDecodeError:
            data = {}

        return {
            "status": response.status,
            "data": data,
            "body": body
        }

    def post_json(self, url, data, headers={}.copy()):
        """
        Encodes data to json and makes http POST with correct headers
        """
        headers = headers.copy()
        headers.update(self.JSON_HEADERS)

        data = bytearray(json.dumps(data), "utf-8")
        req = request.Request(url, data=data, headers=headers, method="POST")

        response = request.urlopen(req)
        body = response.read()

        try:
            data = json.loads(body)
        except json.decoder.JSONDecodeError:
            data = {}

        return {
            "status": response.status,
            "data": data,
            "body": body
        }

class Privat24Business():
    """
    Privat24Business api client
    """
    BASE_URL = "https://link.privatbank.ua/api"
    AUTH_URL = BASE_URL + "/auth/createSession"
    BAUTH_URL = BASE_URL + "/p24BusinessAuth/createSession"
    SEND_OTP_URL = BASE_URL + "/p24BusinessAuth/sendOtp"
    CHECK_OTP_URL = BASE_URL + "/p24BusinessAuth/checkOtp"

    B_ROLE_STR = "ROLE_P24_BUSINESS"

    STATEMENTS_URL = BASE_URL + "/p24b/statements"

    def __init__(self, client_id, client_secret, pb24b_login, pb24b_password, **kwargs):
        self.c_id = client_id
        self.c_secret = client_secret
        self.b_login = pb24b_login
        self.b_password = pb24b_password
        self.http = kwargs.get("http", HTTPCLient())

    def create_session(self):
        """
        Attempt to create session
        Returns dict containing raw response and parsed data
        """

        data = {"clientId": self.c_id,
                "clientSecret": self.c_secret}

        response = self.http.post_json(self.AUTH_URL, data)
        result = {"response": response}

        if response["status"] == 200:
            data = response["data"]
            result.update({
                "session_id": data["id"],
                "expires_in": data["expiresIn"],
                "roles":      data["roles"]
            })

        return result

    def create_b_session(self, session_id):
        """
        Attempt to upgrade simple session to business session
        Returning dict containing raw response and parsed data
        """
        data = {
            "sessionId": session_id,
            "login":     self.b_login,
            "password":  self.b_password
        }
        response = self.http.post_json(self.BAUTH_URL, data)

        result = {"response": response}

        if response["status"] == 200:
            data = response["data"]

            otp_devices = None

            message = data.get("message")
            msg = ""

            if isinstance(message, str):
                msg = message
            elif isinstance(message, list):
                otp_devices = [{"id": m["id"],
                                "number": m["number"]
                                } for m in message]

            result.update({
                "roles": data["roles"],
                "session_id": data["id"],
                "otp_devices": otp_devices,
                "expires_in": data["expiresIn"],
                "msg": msg
            })

        return result

    def select_otp_device(self, session_token, device_id):
        """
        Selects otp device so api will know where to send OTP
        """
        response = self.http.post_json(self.SEND_OTP_URL, {"sessionId": session_token,
                                                           "otpDev": device_id})

        return {
            "response": response
        }

    def send_otp(self, session_token, otp):
        """
        Send OTP to server and receive session on success
        """
        response = self.http.post_json(self.CHECK_OTP_URL, {"sessionId": session_token,
                                                            "otp": otp})

        result = {"response": response}

        if response["status"] == 200:
            data = response["data"]
            result["session_id"] = data["sessionId"]
            result["expires_in"] = data["expiresIn"]

        return result

    def validate_otp(self, session_token, otp_devices, select_otp_fn, get_otp_fn):
        """
        High-level otp validation
        """
        index = select_otp_fn(otp_devices)
        otp_device = otp_devices[index]
        otp_id = otp_device["id"]

        result1 = self.select_otp_device(session_token, otp_id)

        if not result1["response"]["status"]:
            raise Exception("Failed to select given otp device")

        otp = get_otp_fn()
        result = self.send_otp(session_token, otp)

        if result["response"]["status"] != 200:
            raise Exception("Failed to check otp")

        return result

    def full_b_authorize(self, select_otp_fn, get_otp_fn):
        """
        High level business login
        """
        result1 = self.create_session()
        code1 = result1["response"]["status"]
        if code1 != 200:
            raise Exception("Can't create session")

        session_id = result1["session_id"]

        result2 = self.create_b_session(session_id)
        code2 = result2["response"]["status"]
        if code2 != 200:
            raise Exception("Can't create business session, status code %d" % code2)

        otp_devices = result2["otp_devices"]

        if otp_devices:
            result = self.validate_otp(result2["session_id"], otp_devices,
                                       select_otp_fn, get_otp_fn)
            return result

        if not self.B_ROLE_STR in result2["roles"]:
            raise Exception("Didn't get business while authenticated business account")

        return {
            "session_id": result2["session_id"],
            "expires_in": result2["expires_in"]
        }

    def get_statements(self, session_id, start_date, end_date):
        """
        Returns raw statements data
        """
        result = self.http.get_auth_json(self.STATEMENTS_URL,
                                         session_id,
                                         {"stdate": start_date,
                                          "endate": end_date,
                                          "showInf": ""})
        if result["status"] != 200:
            raise Exception("Failed to get statements", result)

        return result["data"]

    @staticmethod
    def parse_statement(statement):
        """
        Decodes statement data into structured dict
        """
        def parse_date(date_str):
            dateformat = "%Y%m%dT%H:%M:%S"
            return datetime.strptime(date_str, dateformat)

        def parse_state(state):
            if state == "r":
                return "done"

            if state == "t":
                return "rollback"

            return None
        def parse_type(_type):
            if _type == "r":
                return "real"

            if _type == "i":
                return "info"

            return None

        amount = statement["amount"]
        amt = float(amount["@amt"])
        amt_cur = amount["@ccy"]
        postdate = parse_date(statement["info"]["@postdate"])
        refp = statement["info"]["@refp"]
        purpose = statement["purpose"]
        credit_acc_number = statement["credit"]["account"]["@number"]
        state = parse_state(statement["info"]["@state"])
        _type = parse_type(statement["info"]["@flinfo"])

        return {
            "amount": amt,
            "currency": amt_cur,
            "postdate": postdate,
            "purpose": purpose,
            "id": refp,
            "credit_acc_number": credit_acc_number,
            "state": state,
            "type": _type
        }

def keyboard_interrupt(func):
    """
    Handles keyboard interrupt gracefully
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Interrupted!")
            sys.exit(1)
    return wrapper

class CLI():
    CONFIGURE = "init"
    GET_B_TOKEN = "get-b-token"
    GET_STATEMENTS = "get-statements"
    ACTIONS = [CONFIGURE, GET_B_TOKEN, GET_STATEMENTS]

    def init(self):
        result = {}
        result["client_id"] = input("Privat24 API client id: ")
        result["client_secret"] = getpass("Privat24 API client secret: ")
        result["business_login"] = input("Privat24 Business Login: ")
        result["business_password"] = getpass("Privat24 Business Password: ")

        config = Config()
        config["credentials"] = result
        config.write_config()

        print(f"Written to {config.PATH}")

    @staticmethod
    def console_b_authorize(api):
        def get_int(prompt):
            try:
                return int(input(prompt))
            except ValueError:
                return None

        def select_otp_dev(otp_devices):
            otp_device_index = None
            while not otp_device_index:
                for i, dev in enumerate(otp_devices):
                    print(i, dev["number"])

                i = get_int("Enter index of otp device:")

                if i in range(len(otp_devices)):
                    otp_device_index = i

        def get_otp():
            return input("Enter your OTP here: ")

        return api.full_b_authorize(select_otp_dev, get_otp)

    def get_b_token(self):
        config = Config()
        api = config.build_p24_client()
        result = self.console_b_authorize(api)

        print(result["session_id"])

    def get_b_statements(self, credit_acc_numbers=None):
        config = Config()
        api = config.build_p24_client()
        result = self.console_b_authorize(api)

        def in_acc_numbers(st):
            nonlocal credit_acc_numbers
            if not credit_acc_numbers:
                return True
            return st["credit_acc_number"] in credit_acc_numbers

        statements = api.get_statements(result["session_id"], "2018-07-01", "2018-07-10")
        statements = filter(in_acc_numbers,
                            map(api.parse_statement,
                                statements))
        print(JSON.dumps(statements))

    def parse_args(self):
        parser = argparse.ArgumentParser(description="Privat24 for Business CLI")

        possible_actions = ", ".join(self.ACTIONS)
        parser.add_argument("action", help=f"Action to do. Possible actions: {possible_actions}")
        parser.add_argument("-A", dest="credit_account_numbers",
                            action="append", help="Show only these account numbers")

        return parser.parse_args()

    @keyboard_interrupt
    def run(self):
        opts = self.parse_args()

        if opts.action == self.CONFIGURE:
            self.init()
        elif opts.action == self.GET_B_TOKEN:
            self.get_b_token()
        elif opts.action == self.GET_STATEMENTS:
            self.get_b_statements(credit_acc_numbers=opts.credit_account_numbers)
        else:
            print(f"Bad arg: {opts.action}")

if __name__ == "__main__":
    CLI().run()
