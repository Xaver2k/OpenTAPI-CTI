"""Lokale IPv4-Adressen für die Auswahl des Empfangsadapters."""
import json
import socket
import subprocess
import sys
from Adapter import private_ip

def normalize_addresses(records):
    addresses = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            address = private_ip(str(record.get("IPAddress", "")))
        except ValueError:
            continue
        alias = str(record.get("InterfaceAlias", "Netzwerkadapter")).strip()
        addresses[address] = alias or "Netzwerkadapter"
    return sorted(addresses.items(), key=lambda entry: (entry[1].casefold(), entry[0]))

def local_addresses():
    if sys.platform == "win32":
        command = (
            "$ErrorActionPreference='Stop'; "
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
            "@(Get-NetIPAddress -AddressFamily IPv4 | "
            "Where-Object { $_.AddressState -eq 'Preferred' } | "
            "Select-Object IPAddress,InterfaceAlias) | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, encoding="utf-8-sig", timeout=12,
            creationflags=subprocess.CREATE_NO_WINDOW, check=True,
        )
        records = json.loads(result.stdout.strip() or "[]")
        return normalize_addresses(records if isinstance(records, list) else [records])
    return normalize_addresses([
        {"IPAddress": address, "InterfaceAlias": "Netzwerkadapter"}
        for address in socket.gethostbyname_ex(socket.gethostname())[2]
    ])
