"""Put messages into a Google Workspace mailbox with the Gmail API: INSERT ONLY.

Nothing is sent, nothing is read back and nothing is deleted. The credential asks for two permissions only: insert mail
(`gmail.insert`) and manage labels (`gmail.labels`). Inserting files a message into the mailbox as it is (like IMAP APPEND), keeping
its date, sender and recipients; it skips spam classification and does not run the mailbox's filters, and the message carries only the
labels it is given (so, without the INBOX label, it never appears in the Inbox).

Two ways to authenticate, both for ONE mailbox:
* a service account with domain-wide delegation, acting as that mailbox (a JSON key file), or
* an OAuth refresh token obtained once by signing in as that mailbox.

The HTTP session is injected so tests never touch the network. Errors are raised in plain words; Google's error text is never passed on.
"""
import base64
import json
import logging
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

log = logging.getLogger(__name__)
TOKEN_URL = "https://oauth2.googleapis.com/token"   # fixed: a key file cannot redirect where credentials are sent
API = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPES = "https://www.googleapis.com/auth/gmail.insert https://www.googleapis.com/auth/gmail.labels"
TIMEOUT = 30
RETRIES = 4


class GoogleError(Exception):
    """A problem to show the person in plain words. Never carries Google's error text."""


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class Auth:
    """Gets (and caches) an access token for the mailbox."""

    def __init__(self, mailbox, *, service_account=None, oauth=None, session=None, clock=time.time):
        if bool(service_account) == bool(oauth):
            raise GoogleError("Give exactly one of a service account key and an OAuth refresh token.")
        self.mailbox, self.sa, self.oauth, self.session, self.clock = mailbox, service_account, oauth, session or requests.Session(), clock
        self._token, self._expires = "", 0.0

    @classmethod
    def from_settings(cls, settings, session=None):
        if settings.GOOGLE_SERVICE_ACCOUNT_FILE:
            try:
                with open(settings.GOOGLE_SERVICE_ACCOUNT_FILE, encoding="utf-8") as fh:
                    key = json.load(fh)
                key["client_email"], key["private_key"]  # noqa: B018: must be there
            except (OSError, ValueError, KeyError):
                raise GoogleError("The Google service account key file cannot be read or is not a valid key file.") from None
            return cls(settings.ARCHIVE_SYNC_MAILBOX, service_account=key, session=session)
        return cls(settings.ARCHIVE_SYNC_MAILBOX, session=session, oauth={
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID, "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET, "refresh_token": settings.GOOGLE_OAUTH_REFRESH_TOKEN})

    def _assertion(self):
        now = int(self.clock())
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = _b64(json.dumps({"iss": self.sa["client_email"], "sub": self.mailbox, "scope": SCOPES, "aud": TOKEN_URL, "iat": now, "exp": now + 3600}).encode())
        try:
            key = serialization.load_pem_private_key(self.sa["private_key"].encode(), password=None)
            sig = key.sign(head + b"." + claims, padding.PKCS1v15(), hashes.SHA256())
        except Exception:  # noqa: BLE001: a malformed key is a configuration problem, said plainly
            raise GoogleError("The Google service account key is not a valid private key.") from None
        return (head + b"." + claims + b"." + _b64(sig)).decode()

    def token(self, force=False):
        if self._token and not force and self.clock() < self._expires - 60:
            return self._token
        if self.sa:
            data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self._assertion()}
        else:
            data = {"grant_type": "refresh_token", **self.oauth}
        try:
            resp = self.session.post(TOKEN_URL, data=data, timeout=TIMEOUT)
            body = resp.json() if resp.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            raise GoogleError("Google could not be reached to get an access token.") from None
        if resp.status_code != 200 or not body.get("access_token"):
            log.warning("google token request refused (HTTP %s)", resp.status_code)
            raise GoogleError("Google refused the credentials. Check that the key or token is current and that the mailbox is authorised "
                              "for the two Gmail permissions (insert and labels).")
        self._token, self._expires = body["access_token"], self.clock() + int(body.get("expires_in", 3600))
        return self._token


class Gmail:
    def __init__(self, auth, session=None, sleep=time.sleep):
        self.auth, self.session, self._sleep = auth, session or auth.session, sleep
        self._labels = None

    def _call(self, method, path, **kw):
        refreshed = False
        for attempt in range(RETRIES):
            try:
                resp = self.session.request(method, API + path, headers={"Authorization": "Bearer " + self.auth.token(force=refreshed)}, timeout=TIMEOUT, **kw)
            except requests.RequestException:
                resp = None
            if resp is not None and resp.status_code == 401 and not refreshed:
                refreshed = True       # the token may have expired early: get a new one once
                continue
            if resp is not None and (resp.status_code in (429, 500, 502, 503, 504)) or resp is None:
                self._sleep(min(2 ** attempt, 20))
                continue
            return resp
        raise GoogleError("Google did not answer (it kept refusing or timing out). It will be tried again.")

    def labels(self, refresh=False):
        if self._labels is None or refresh:
            resp = self._call("GET", "/labels")
            if resp.status_code != 200:
                raise GoogleError(self._why(resp, "The labels of the mailbox could not be listed."))
            self._labels = {lb["name"].lower(): lb["id"] for lb in resp.json().get("labels", [])}
        return self._labels

    def label(self, name):
        """The id of a label, created if it does not exist. Label names are case-insensitive in Gmail."""
        found = self.labels().get(name.lower())
        if found:
            return found
        resp = self._call("POST", "/labels", json={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"})
        if resp.status_code == 409:                      # created in the meantime
            found = self.labels(refresh=True).get(name.lower())
            if found:
                return found
        if resp.status_code not in (200, 201):
            raise GoogleError(self._why(resp, "A label could not be created in the mailbox."))
        self._labels[name.lower()] = resp.json()["id"]
        return self._labels[name.lower()]

    def insert(self, raw, label_ids):
        """File a raw RFC 822 message into the mailbox with exactly these labels. Returns the Gmail message id."""
        resp = self._call("POST", "/messages?internalDateSource=dateHeader", json={"raw": _b64(raw).decode(), "labelIds": list(label_ids)})
        if resp.status_code not in (200, 201):
            raise GoogleError(self._why(resp, "Google refused to file a message into the mailbox."))
        return resp.json().get("id", "")

    def check(self):
        """-> number of labels. Proves the credential works (token, mailbox authorised, labels readable)."""
        return len(self.labels(refresh=True))

    @staticmethod
    def _why(resp, default):
        if resp.status_code in (401, 403):
            return "Google refused: the mailbox is not authorised for the two Gmail permissions (insert and labels), or the credential is wrong."
        return default
