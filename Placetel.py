"""Vermittelte Wahl über die dokumentierte Placetel-Profi-API."""
import base64
import ctypes
from ctypes import wintypes
import http.client
import json
import re

class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.c_void_p)]

def windows_secret(value, protect):
    """DPAPI-Schlüssel des angemeldeten Windows-Benutzers verwenden."""
    raw = value.encode("ascii") if protect else base64.b64decode(value, validate=True)
    buffer = ctypes.create_string_buffer(raw)
    source = Blob(len(raw), ctypes.cast(buffer, ctypes.c_void_p))
    result = Blob()
    api = ctypes.WinDLL("crypt32", use_last_error=True)
    operation = api.CryptProtectData if protect else api.CryptUnprotectData
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise OSError("API-Schlüssel für diesen Windows-Benutzer nicht lesbar oder speicherbar.")
    try:
        out = ctypes.string_at(result.data, result.size)
        return base64.b64encode(out).decode("ascii") if protect else out.decode("ascii")
    finally:
        ctypes.memset(result.data, 0, result.size)
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(result.data))

def check_token(value):
    if not re.fullmatch(r"[!-~]{1,4096}", value):
        raise ValueError("Bitte den API-Schlüssel ohne Leerzeichen oder Zeilenumbruch einfügen.")

class PlacetelDial:
    def __init__(self, cfg):
        self.uid = cfg.get("sipuid","")
        if not re.fullmatch(r"[a-zA-Z0-9._+-]{1,128}@[a-zA-Z0-9.-]{1,190}", self.uid):
            raise ValueError("Vollständige SIP-UID des VoIP-Ziels angeben, einschließlich @ und Domain.")
        self.token = windows_secret(cfg.get("api_dpapi",""), False)
        check_token(self.token)

    def dial(self, number):
        if not re.fullmatch(r"\+?[0-9]{1,32}", number):
            raise ValueError("Ungültige Zielnummer.")
        conn = http.client.HTTPSConnection("api.placetel.de", timeout=8)
        try:
            data = json.dumps({"sipuid":self.uid, "target":number}).encode("utf-8")
            conn.request("POST", "/v2/calls", data, {"Content-Type":"application/json",
                         "Authorization":"Bearer " + self.token})
            response = conn.getresponse()
            if response.status != 201:
                raise OSError(f"Placetel antwortet mit HTTP {response.status}. SIP-UID, Ziel und API-Berechtigung prüfen.")
        finally:
            conn.close()
