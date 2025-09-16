"""
graph_mailer.py
Python port of the PHP graphMailer class (Katy Nicholson)
Requires: requests
"""

from typing import Any, Dict, List, Optional
import requests
import json
import base64
import time
import urllib.parse


class GraphMailer:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, verify_ssl: bool = True):
        """
        tenant_id, client_id, client_secret: Azure AD app credentials (client credentials flow)
        verify_ssl: pass False for debugging / self-signed certs (not recommended in prod)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://graph.microsoft.com/v1.0/"
        self.verify_ssl = verify_ssl
        self.token = self._get_token()

    def _get_token(self) -> str:
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": self.client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }
        r = requests.post(url, data=data, verify=self.verify_ssl)
        r.raise_for_status()
        reply = r.json()
        return reply["access_token"]

    def _auth_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        if extra:
            headers.update(extra)
        return headers

    # -------------------------
    # Helpers for HTTP actions
    # -------------------------
    def _send_get(self, url: str) -> str:
        print(url)
        r = requests.get(url, headers=self._auth_headers(), verify=self.verify_ssl)
        r.raise_for_status()
        return r.text

    def _send_delete(self, url: str) -> str:
        print(url)
        r = requests.delete(url, headers=self._auth_headers(), verify=self.verify_ssl)
        # some APIs return 204/200 or a json error
        if r.status_code >= 400:
            r.raise_for_status()
        return r.text

    def _send_post(self, url: str, payload: Any = None, headers: Optional[List[str]] = None) -> Dict[str, Any]:
        print(url)
        # headers param here is list of header strings in PHP version; convert if provided
        extra = {}
        if headers:
            # convert list like ["Content-type: application/json", ...] into dict
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    extra[k.strip()] = v.strip()
        final_headers = self._auth_headers(extra)
        if payload is None:
            # Some endpoints expect an empty body but Content-Length: 0 in PHP version.
            r = requests.post(url, headers=final_headers, data="", verify=self.verify_ssl)
        else:
            # payload may be already JSON string or dict
            if isinstance(payload, (dict, list)):
                r = requests.post(url, headers=final_headers, json=payload, verify=self.verify_ssl)
            else:
                # assume string
                r = requests.post(url, headers=final_headers, data=payload, verify=self.verify_ssl)
        return {"code": r.status_code, "data": r.text}

    def _send_patch(self, url: str, payload: Any = None, headers: Optional[List[str]] = None) -> Dict[str, Any]:
        print(url)
        extra = {}
        if headers:
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    extra[k.strip()] = v.strip()
        final_headers = self._auth_headers(extra)
        if isinstance(payload, (dict, list)):
            r = requests.patch(url, headers=final_headers, json=payload, verify=self.verify_ssl)
        else:
            r = requests.patch(url, headers=final_headers, data=payload, verify=self.verify_ssl)
        return {"code": r.status_code, "data": r.text}

    # -------------------------
    # Core functionality
    # -------------------------
    def create_message_json(self, message_args: Dict[str, Any], add_message_envelope: bool = False) -> str:
        """
        message_args fields (same semantics as PHP):
          subject, replyTo {name,address}, toRecipients [ {name?, address} ], ccRecipients, bccRecipients,
          importance, conversationId, body (HTML), images[], attachments[], comment
        """
        msg = {}

        def _add_recipients(key: str, target_key: str):
            if key in message_args:
                arr = []
                for r in message_args[key]:
                    if "name" in r:
                        arr.append({"emailAddress": {"name": r["name"], "address": r["address"]}})
                    else:
                        arr.append({"emailAddress": {"address": r["address"]}})
                msg[target_key] = arr

        _add_recipients("toRecipients", "toRecipients")
        _add_recipients("ccRecipients", "ccRecipients")
        _add_recipients("bccRecipients", "bccRecipients")

        if "subject" in message_args:
            msg["subject"] = message_args["subject"]
        if "importance" in message_args:
            msg["importance"] = message_args["importance"]
        if "replyTo" in message_args:
            msg["replyTo"] = [{"emailAddress": {"name": message_args["replyTo"].get("name"), "address": message_args["replyTo"]["address"]}}]
        if "body" in message_args:
            msg["body"] = {"contentType": "HTML", "content": message_args["body"]}

        if add_message_envelope:
            envelope = {"message": msg}
            if "comment" in message_args:
                envelope["comment"] = message_args["comment"]
            # if message empty, keep consistent with PHP (it unsets empty); here we allow empty message
            return json.dumps(envelope)
        return json.dumps(msg)

    def get_message(self, mailbox: str, message_id: str, folder: str = "") -> Optional[Dict[str, Any]]:
        if folder:
            url = f"{self.base_url}users/{mailbox}/mailFolders/{folder}/messages/{message_id}"
        else:
            url = f"{self.base_url}users/{mailbox}/messages/{message_id}"
        try:
            response = self._send_get(url)
            message = json.loads(response)
            if "error" in message:
                return None
            return message
        except requests.HTTPError:
            return None

    def get_messages(self, mailbox: str, folder: str = "inbox", filter_q: str = "", get_attachments: bool = True) -> List[Dict[str, Any]]:
        """
        Returns list of simplified message dicts similar to PHP version.
        filter_q may include OData query parameters (without '?' prefix). Function will URL-encode some chars.
        """
        if not self.token:
            raise RuntimeError("No token defined")

        # ensure conversation topic expanded property like PHP example
        if filter_q:
            filter_q += "&$expand=singleValueExtendedProperties($filter=id eq 'string 0x0070')"
        else:
            filter_q = "$expand=singleValueExtendedProperties($filter=id eq 'string 0x0070')"

        # URL-encode unsafe characters but leave OData operators intact; we mimic the PHP behaviour simply:
        encoded = urllib.parse.quote(filter_q, safe="=&$(),'-/")  # keep common OData chars safe
        url = f"{self.base_url}users/{mailbox}/mailFolders/{folder}/messages?{encoded}"
        rtext = self._send_get(url)
        message_list = json.loads(rtext)
        if "error" in message_list:
            raise RuntimeError(f"{message_list['error'].get('code')} {message_list['error'].get('message')}")

        result = []
        # template of fields like PHP
        for mail_item in message_list.get("value", []):
            # copy known fields and provide defaults
            msg = {
                "id": mail_item.get("id"),
                "sentDateTime": mail_item.get("sentDateTime"),
                "subject": mail_item.get("subject"),
                "bodyPreview": mail_item.get("bodyPreview"),
                "importance": mail_item.get("importance"),
                "conversationId": mail_item.get("conversationId"),
                "isRead": mail_item.get("isRead"),
                "body": mail_item.get("body"),
                "sender": mail_item.get("sender"),
                "toRecipients": mail_item.get("toRecipients", []),
                "ccRecipients": mail_item.get("ccRecipients", []),
                "toRecipientsBasic": self.basic_address(mail_item.get("toRecipients", [])),
                "ccRecipientsBasic": self.basic_address(mail_item.get("ccRecipients", [])),
                "replyTo": mail_item.get("replyTo", []),
                "attachments": None,
                "conversationTopic": None,
            }

            # attachments
            attachments = None
            if get_attachments:
                try:
                    att_text = self._send_get(f"{self.base_url}users/{mailbox}/messages/{msg['id']}/attachments")
                    att_list = json.loads(att_text).get("value", [])
                    if att_list:
                        # handle referenceAttachment special message like PHP
                        for a in att_list:
                            if a.get("@odata.type") == "#microsoft.graph.referenceAttachment":
                                a["contentBytes"] = base64.b64encode(b"This is a link to a SharePoint online file, not yet supported").decode()
                                a["isInline"] = 0
                        attachments = att_list
                except requests.HTTPError:
                    attachments = None
            msg["attachments"] = attachments

            # singleValueExtendedProperties (conversation topic)
            svp = mail_item.get("singleValueExtendedProperties", [])
            for prop in svp:
                # PHP checked id == "String 0x70" or "string 0x0070" above we expanded 0x0070
                if prop.get("id", "").lower().endswith("0x70"):
                    msg["conversationTopic"] = prop.get("value")
            result.append(msg)
        return result

    def get_folder_id(self, mailbox: str, folder_name: str) -> Optional[str]:
        url = f"{self.base_url}users/{mailbox}/mailFolders?$select=displayName&$top=100"
        rtext = self._send_get(url)
        folder_list = json.loads(rtext).get("value", [])
        for folder in folder_list:
            if folder.get("displayName") == folder_name:
                return folder.get("id")

        # try subfolders
        for folder in folder_list:
            child_url = f"{self.base_url}users/{mailbox}/mailFolders/{folder.get('id')}/childFolders?$select=displayName&$top=100"
            child_text = self._send_get(child_url)
            child_list = json.loads(child_text).get("value", [])
            for child in child_list:
                if child.get("displayName") == folder_name:
                    return child.get("id")
        return None

    def delete_email(self, mailbox: str, message_id: str, move_to_deleted_items: bool = True, folder: str = "") -> Any:
        if move_to_deleted_items:
            if folder:
                url = f"{self.base_url}users/{mailbox}/mailFolders/{folder}/messages/{message_id}/move"
            else:
                url = f"{self.base_url}users/{mailbox}/messages/{message_id}/move"
            body = {"destinationId": "deleteditems"}
            resp = self._send_post(url, body, headers=["Content-type: application/json"])
        else:
            if folder:
                url = f"{self.base_url}users/{mailbox}/mailFolders/{folder}/messages/{message_id}"
            else:
                url = f"{self.base_url}users/{mailbox}/messages/{message_id}"
            resp_text = self._send_delete(url)
            # _send_delete raises for non-2xx, so if we get here it's OK
            return True

        # Inspect response like PHP's decoding
        code = resp.get("code")
        data_text = resp.get("data")
        try:
            obj = json.loads(data_text) if data_text else None
        except Exception:
            obj = None
        if obj and obj.get("error", {}).get("code") == "ErrorItemNotFound":
            return obj
        return True if code in (200, 201, 202) else False

    def send_mail(self, mailbox: str, message_args: Dict[str, Any], delete_after_send: bool = False) -> Any:
        """
        message_args should include images[] and attachments[] similar to the PHP version:
         images: [{Name, Content (bytes), ContentType, ContentID}], attachments: [{Name, Content (bytes), ContentType}]
        """
        if not self.token:
            raise RuntimeError("No token defined")

        message_json = json.loads(self.create_message_json(message_args))
        # Create message (POST /users/{mailbox}/messages)
        resp = self._send_post(f"{self.base_url}users/{mailbox}/messages", message_json, headers=["Content-type: application/json"])
        if resp["code"] >= 400:
            return False
        responsedata = json.loads(resp["data"])
        message_id = responsedata.get("id")

        # add inline images
        for image in message_args.get("images", []):
            att = {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": image["Name"],
                "contentBytes": base64.b64encode(image["Content"]).decode(),
                "contentType": image.get("ContentType"),
                "isInline": True,
                "contentId": image.get("ContentID"),
            }
            self._send_post(f"{self.base_url}users/{mailbox}/messages/{message_id}/attachments", att, headers=["Content-type: application/json"])

        # add attachments
        for attachment in message_args.get("attachments", []):
            att = {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": attachment["Name"],
                "contentBytes": base64.b64encode(attachment["Content"]).decode(),
                "contentType": attachment.get("ContentType"),
                "isInline": False,
            }
            self._send_post(f"{self.base_url}users/{mailbox}/messages/{message_id}/attachments", att, headers=["Content-type: application/json"])

        # Send message
        send_resp = self._send_post(f"{self.base_url}users/{mailbox}/messages/{message_id}/send", "", headers=["Content-Length: 0"])
        if delete_after_send:
            # try to delete from sentitems
            self.delete_email(mailbox, message_id, move_to_deleted_items=False, folder="sentitems")
            # in PHP it sets $messageID = true
            message_id = True

        if send_resp["code"] == 202:
            return message_id
        return False

    def reply(self, mailbox: str, message_id: str, message_args: Dict[str, Any], save_only: bool = False, delete_after_send: bool = False) -> Any:
        """
        Creates a reply draft, optionally sends it, optionally deletes after send.
        """
        message_json = json.loads(self.create_message_json(message_args, add_message_envelope=True))
        resp = self._send_post(f"{self.base_url}users/{mailbox}/messages/{message_id}/createReply", message_json, headers=["Content-type: application/json"])
        responsedata = json.loads(resp["data"])
        new_message_id = responsedata.get("id")

        if not save_only:
            if delete_after_send:
                time.sleep(3)  # try to flush mailbox like PHP
            self._send_post(f"{self.base_url}users/{mailbox}/messages/{new_message_id}/send", False, headers=["Content-type: application/json"])
            if delete_after_send:
                return self.delete_email(mailbox, new_message_id, move_to_deleted_items=False, folder="sentitems")
        return new_message_id

    def update_message(self, mailbox: str, message_id: str, fields: Dict[str, Any], folder: str = "") -> Any:
        if folder:
            url = f"{self.base_url}users/{mailbox}/mailFolders/{folder}/messages/{message_id}"
        else:
            url = f"{self.base_url}users/{mailbox}/messages/{message_id}"
        resp = self._send_patch(url, fields, headers=["Content-type: application/json"])
        if resp["code"] in (200, 204):
            return True
        return resp

    def create_event(self, mailbox: str, event_obj: Dict[str, Any]) -> Any:
        resp = self._send_post(f"{self.base_url}users/{mailbox}/calendar/events", event_obj, headers=["Content-type: application/json"])
        if resp["code"] == 201:
            return json.loads(resp["data"]).get("id")
        return resp

    def update_event(self, mailbox: str, event_id: str, event_obj: Dict[str, Any]) -> Any:
        resp = self._send_patch(f"{self.base_url}users/{mailbox}/calendar/events/{event_id}", event_obj, headers=["Content-type: application/json"])
        if resp["code"] in (200, 204):
            return True
        return resp

    def cancel_event(self, mailbox: str, event_id: str, comment: str) -> Any:
        event_json = {"comment": comment}
        resp = self._send_post(f"{self.base_url}users/{mailbox}/calendar/events/{event_id}/cancel", event_json, headers=["Content-type: application/json"])
        if resp["code"] == 202:
            return True
        return resp

    def get_events(self, mailbox: str, filter_q: str = "") -> Any:
        if filter_q:
            # mimic PHP's crude URL escape
            filter_q = filter_q.replace(":", "%3A").replace("/", "%2F").replace(" ", "%20")
            url = f"{self.base_url}users/{mailbox}/events?{filter_q}"
        else:
            url = f"{self.base_url}users/{mailbox}/events"
        resp = self._send_get(url)
        return json.loads(resp)

    def basic_address(self, addresses: List[Dict[str, Any]]) -> List[str]:
        ret = []
        for a in addresses:
            # a typically has shape { "emailAddress": { "address": "..."}}
            ea = a.get("emailAddress", {})
            if "address" in ea:
                ret.append(ea["address"])
        return ret


# Example usage:
# gm = GraphMailer("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")
# msgs = gm.get_messages("service@contoso.com", folder="inbox")
# print(msgs)
