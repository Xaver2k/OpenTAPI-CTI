"""Fenster und Ereignisempfänger für einen Arbeitsplatz."""
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from Network import local_addresses
from Placetel import PlacetelDial, check_token, windows_secret
from Adapter import Calls, EVENTS, NUMBER, ROOT, Server, Yealink, dial_number, handler, private_ip, event_url, event_tls

CONFIG = ROOT / "adapter.json"
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
LABELS = ("Eingehender Anruf", "Ausgehender Anruf", "Verbindung hergestellt",
          "Gespräch beendet", "Verpasster Anruf")

PROFILES = {
    "yealink": "Yealink · lokal wählen und Anrufe erkennen",
    "yealink_api": "Yealink · Placetel-Wahl und lokale Anruferkennung",
    "snom": "snom · Placetel-Wahl und lokale Anruferkennung",
    "api": "Cisco / andere · nur Placetel-Wahl",
}

def profile(cfg):
    return cfg.get("profil", "api" if cfg.get("zentral") else "yealink")

def startup(enable=None):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        if enable is True:
            frozen = getattr(sys, "frozen", False)
            pythonw = Path(sys.executable) if frozen else Path(sys.executable).with_name("pythonw.exe")
            if not pythonw.is_file():
                raise OSError("pythonw.exe fehlt in der Python-Installation.")
            args = [str(pythonw)]
            if not frozen:
                args.append(str(Path(__file__).resolve()))
            command = subprocess.list2cmdline(args + ["--minimiert"])
            winreg.SetValueEx(key, "OpenTapiCti", 0, winreg.REG_SZ, command)
        elif enable is False:
            try:
                winreg.DeleteValue(key, "OpenTapiCti")
            except FileNotFoundError:
                pass
        try:
            return bool(winreg.QueryValueEx(key, "OpenTapiCti")[0])
        except FileNotFoundError:
            return False

def validate(cfg):
    if profile(cfg) not in PROFILES:
        raise ValueError("Unbekanntes Telefonprofil.")
    if profile(cfg) != "api" and private_ip(cfg["pc"]) == private_ip(cfg["telefon"]):
        raise ValueError("PC und Telefon benötigen unterschiedliche private IPv4-Adressen.")
    if not re.fullmatch(r"[0-9]{1,16}", cfg["nebenstelle"]):
        raise ValueError("Die Durchwahl muss aus 1 bis 16 Ziffern bestehen.")
    for key in ("token", "lokal"):
        if not re.fullmatch(r"[0-9a-f]{48}", cfg[key]):
            raise ValueError("Ungültiger Schlüssel in der Konfiguration.")
    if cfg.get("zentral"):
        PlacetelDial(cfg)
    else:
        Yealink(cfg)
    return cfg

def save(cfg):
    ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=ROOT, delete=False, mode="w", encoding="utf8") as f:
        tmp = Path(f.name)
    try:
        tmp.write_text(json.dumps(cfg, indent=2), encoding="utf8")
        os.replace(tmp, CONFIG)
    finally:
        tmp.unlink(missing_ok=True)

class Window:
    def __init__(self, root):
        self.root = root
        root.title("OpenTapiCti · Arbeitsplatz")
        assets = Path(__file__).resolve().parent / "assets"
        self.window_icon = tk.PhotoImage(file=str(assets / "OpenTapiCti.png"))
        root.iconphoto(True, self.window_icon)
        if sys.platform == "win32":
            root.iconbitmap(str(assets / "OpenTapiCti.ico"))
        self.cfg = {}
        self.cert, self.key = "", ""
        self.mode = tk.StringVar(value=PROFILES["yealink"])
        self.uid = tk.StringVar()
        self.api = tk.StringVar()
        self.servers = []
        self.events = queue.Queue(maxsize=64)
        self.status = tk.StringVar(value="Bitte Arbeitsplatz einrichten.")
        self.pc, self.phone, self.ext = (tk.StringVar() for _ in range(3))
        self.pc_choices = {}
        self.address_updates = queue.Queue()
        self.address_scanning = False
        self.after = tk.BooleanVar(value=True)
        self.http = tk.BooleanVar()
        self.auto = tk.BooleanVar()
        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(1, weight=1)
        for i,(name,var) in enumerate([("IP dieses PCs", self.pc), ("IP des Tischtelefons",self.phone),("Eigene Durchwahl",self.ext)]):
            ttk.Label(outer,text=name).grid(row=i,column=0,sticky="w",padx=(0,12),pady=4)
            if var is self.pc:
                row = ttk.Frame(outer)
                row.grid(row=i,column=1,sticky="ew")
                row.columnconfigure(0,weight=1)
                self.pc_box = ttk.Combobox(row,textvariable=var,width=28)
                self.pc_box.grid(row=0,column=0,sticky="ew")
                ttk.Button(row,text="Aktualisieren",command=self.scan_addresses).grid(row=0,column=1,padx=(5,0))
            else:
                ttk.Entry(outer,textvariable=var,width=28).grid(row=i,column=1,sticky="ew")
        for row,text,var,fn in [(3,"Eingehende Anrufe erst nach Annahme an THEORG melden",self.after,None),
                                (4,"Fernwahl per HTTP erlauben (unverschlüsselt)",self.http,None),
                                (5,"Bei Windows-Anmeldung minimiert starten",self.auto,self.set_auto)]:
            ttk.Checkbutton(outer,text=text,variable=var,command=fn).grid(row=row,columnspan=2,sticky="w",pady=3)
        ttk.Label(outer,text="Telefonprofil").grid(row=6,column=0,sticky="w")
        ttk.Combobox(outer,textvariable=self.mode,values=list(PROFILES.values()),state="readonly",width=47).grid(row=6,column=1,sticky="ew")

        for i,(label,var,mask) in enumerate([("Placetel SIP-UID",self.uid,""),("API-Schlüssel (leer = beibehalten)",self.api,"*")],7):
            ttk.Label(outer,text=label).grid(row=i,column=0,sticky="w",pady=3)
            ttk.Entry(outer,textvariable=var,show=mask).grid(row=i,column=1,sticky="ew")
        bar = ttk.Frame(outer)
        bar.grid(row=9,columnspan=2,sticky="w",pady=12)
        for label,fn in [("Speichern und starten", self.apply),("Telefon einrichten",self.urls),("Testanruf",self.test),("Empfangsschutz",self.tls_dialog)]:
            ttk.Button(bar,text=label,command=fn).pack(side="left",padx=(0,5))
        ttk.Separator(outer).grid(row=10,columnspan=2,sticky="ew")
        ttk.Label(outer,textvariable=self.status,wraplength=450).grid(row=11,columnspan=2,sticky="w",pady=(9,0))
        try:
            self.auto.set(startup())
            if CONFIG.exists():
                self.cfg = validate(json.loads(CONFIG.read_text(encoding="utf8")))
                for key,var in [("pc",self.pc),("telefon",self.phone),("nebenstelle",self.ext)]:
                    var.set(self.cfg[key])
                self.cert, self.key = self.cfg.get("cert",""), self.cfg.get("key","")
                self.mode.set(PROFILES[profile(self.cfg)])
                self.uid.set(self.cfg.get("sipuid",""))
                self.after.set(self.cfg.get("nach_annahme",True))
                self.http.set(self.cfg["schema"] == "http")
                self.start(self.cfg)
                if "--minimiert" in sys.argv:
                    root.after(150,root.iconify)

        except Exception as exc:
            self.status.set("Start fehlgeschlagen. " + str(exc))
        self.scan_addresses()
        root.protocol("WM_DELETE_WINDOW",self.close)
        root.after(200,self.refresh)

    def scan_addresses(self):
        if self.address_scanning:
            return
        self.address_scanning = True
        def scan():
            try:
                self.address_updates.put((local_addresses(), None))
            except (OSError, ValueError, subprocess.SubprocessError):
                self.address_updates.put(([], "IP-Erkennung fehlgeschlagen. IP manuell eintragen oder Aktualisieren wählen."))
        threading.Thread(target=scan,daemon=True).start()

    def receive_addresses(self, addresses, error):
        self.address_scanning = False
        current = self.pc_choices.get(self.pc.get(), self.pc.get().strip())
        self.pc_choices = {f"{ip} · {name}": ip for ip, name in addresses}
        self.pc_box.configure(values=list(self.pc_choices))
        match = next((label for label, ip in self.pc_choices.items() if ip == current), None)
        if match:
            self.pc.set(match)
        elif current:
            self.pc.set(current)
        elif len(addresses) == 1:
            self.pc.set(next(iter(self.pc_choices)))
        if error:
            self.status.set(error)
        elif not current and len(addresses) > 1:
            self.status.set("Mehrere PC-Adressen gefunden. Bitte den Adapter zum Telefon auswählen.")
        elif not addresses:
            self.status.set("Keine geeignete private IPv4 gefunden. Netzwerk prüfen oder IP manuell eintragen.")

    def set_auto(self):
        try:
            if self.auto.get() and not self.servers:
                raise ValueError("Bitte zuerst speichern und starten.")
            startup(self.auto.get())
        except (OSError,ValueError) as exc:
            self.auto.set(not self.auto.get())
            messagebox.showerror("Autostart",str(exc))

    def event(self, event, has_number):
        words = {"in":"Eingehender Ruf","up":"Gespräch verbunden","out":"Ausgehender Ruf",
                 "end":"Ruf beendet","wahlfehler":"Wählbefehl abgelehnt"}
        self.report(time.strftime("%H:%M:%S") + " · " + words[event] +
                    (" · Rufnummer vorhanden" if has_number else ""))

    def report(self,text):
        try:
            self.events.put_nowait(text)
        except queue.Full:
            pass

    def refresh(self):
        while not self.address_updates.empty():
            self.receive_addresses(*self.address_updates.get_nowait())
        while not self.events.empty():
            self.status.set(self.events.get_nowait())
        self.root.after(200,self.refresh)

    def start(self,cfg):
        calls = Calls(cfg.get("nach_annahme", True))
        phone = PlacetelDial(cfg) if cfg.get("zentral") else Yealink(cfg)
        try:
            for local,addr,port,source in [(False,cfg["pc"],18762,cfg["telefon"]),(True,"127.0.0.1",18763,"127.0.0.1")]:
                if not local and profile(cfg) == "api":
                    continue
                s = Server((addr,port),handler(cfg,calls,phone,local,self.event))
                try:
                    if not local:
                        event_tls(s,cfg)
                except Exception:
                    s.server_close()
                    raise
                s.allowed_ip = source
                threading.Thread(target=s.serve_forever,kwargs={"poll_interval":0.05},daemon=True).start()
                self.servers.append(s)
        except (OSError, ValueError) as exc:
            self.stop()
            raise OSError("Empfänger konnte nicht starten. PC-IP, belegte Ports und gegebenenfalls Zertifikat/Schlüssel prüfen.") from None
        if profile(cfg) == "api":
            self.status.set("Placetel-Wahl bereit · Eingehende Anrufe werden in diesem Modus nicht gemeldet.")
            return
        self.status.set("Empfänger läuft · Durchwahl " + cfg["nebenstelle"] + " · Warte auf Telefonereignis.")

    def stop(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.servers.clear()

    def apply(self):
        try:
            if CONFIG.exists() and not self.cfg:
                raise ValueError("Konfiguration konnte nicht geladen werden. Vor Änderungen bestehende Datei prüfen.")
            selected = next(key for key, label in PROFILES.items() if self.mode.get() == label)
            central = selected != "yealink"
            protected = self.cfg.get("api_dpapi","")
            if central and self.api.get().strip():
                token = self.api.get().strip()
                check_token(token)
                protected = windows_secret(token,True)
            if central and not protected:
                raise ValueError("Bitte den Placetel-API-Schlüssel eintragen.")
            cfg = validate(dict(self.cfg, profil=selected,zentral=central,api_dpapi=protected,sipuid=self.uid.get().strip(),pc=self.pc_choices.get(self.pc.get(),self.pc.get().strip()), telefon=self.phone.get().strip(),
                nebenstelle=self.ext.get().strip(), schema="http" if self.http.get() else "https",
                cert=self.cert,key=self.key,nach_annahme=self.after.get(),token=self.cfg.get("token") or secrets.token_hex(24),
                lokal=self.cfg.get("lokal") or secrets.token_hex(24)))
            if not cfg.get("zentral") and cfg["schema"] == "http" and self.cfg.get("schema") != "http" and not messagebox.askyesno("Unverschlüsselte Fernwahl","Die Zielrufnummer wird im LAN unverschlüsselt übertragen. Für diesen Test zulassen?"):
                return
            if selected != "api" and not self.cert and (not self.cfg or self.cfg.get("cert") or profile(self.cfg) == "api"):
                if not messagebox.askyesno("HTTP-Empfang im Testnetz","Das Telefon sendet Rufnummer und URL-Schlüssel unverschlüsselt. Im abgeschotteten Bürotest zulassen? Für HTTPS zuerst „Empfangsschutz“ öffnen."):
                    return
            self.stop()
            try:
                self.start(cfg)
                save(cfg)
            except Exception:
                self.stop()
                if self.cfg:
                    self.start(self.cfg)
                raise
            self.cfg = cfg
            self.api.set("")
        except (OSError,ValueError) as exc:
            messagebox.showerror("Arbeitsplatz",str(exc))

    def tls_dialog(self):
        box = tk.Toplevel(self.root)
        box.title("Ereignisse vom Telefon empfangen")
        frame = ttk.Frame(box,padding=15)
        frame.pack()
        ttk.Label(frame,text="Für HTTPS ein Zertifikat für die PC-IP wählen, dem das Telefon vertraut. Der private PEM-Schlüssel muss für den Arbeitsplatzbenutzer lesbar sein.",wraplength=420).pack(pady=6)
        def choose():
            cert = filedialog.askopenfilename(parent=box,title="Zertifikatskette (PEM) wählen")
            if not cert:
                return
            key = filedialog.askopenfilename(parent=box,title="Privaten Schlüssel (PEM ohne Passphrase) wählen")
            if key:
                self.cert, self.key = cert,key
                self.status.set("HTTPS ausgewählt. Speichern und die neuen URLs im Telefon eintragen.")
                box.destroy()
        def clear():
            self.cert, self.key = "", ""
            self.status.set("HTTP ausgewählt. Bitte speichern und die URLs im Telefon anpassen.")
            box.destroy()
        ttk.Label(frame,text="Ausgewählt: " + ("HTTPS" if self.cert else "HTTP")).pack()
        ttk.Button(frame,text="HTTPS-Zertifikat und Schlüssel wählen",command=choose).pack(fill="x",pady=4)
        ttk.Button(frame,text="HTTP im abgeschotteten Testnetz",command=clear).pack(fill="x")

    def urls(self):
        if profile(self.cfg) == "api":
            messagebox.showinfo("Telefon einrichten","Im zentralen Wahlmodus ist keine Telefonkonfiguration nötig.")
            return
        if not self.cfg:
            messagebox.showinfo("Telefon einrichten","Bitte zuerst speichern und starten.")
            return
        w = tk.Toplevel(self.root)
        w.title("Tischtelefon einmalig einrichten")
        f = ttk.Frame(w,padding=16)
        f.pack()
        text = ("1. Im Telefon unter Features → Remote Control diese PC-IP zulassen: " + self.cfg["pc"] +
                "\n2. Unter Features → Action URL vorhandene Einträge sichern. Dann jede URL in das zugehörige Feld kopieren und bestätigen.\n3. Telefon anrufen, abheben und den Status im Hauptfenster prüfen.")
        fields = list(EVENTS.items())
        if profile(self.cfg) in ("snom", "yealink_api"):
            text = "Vorhandene Action URLs im Telefon sichern. Für jedes Ereignis die passende URL eintragen. Die Fernwahl erfolgt über Placetel."
        if profile(self.cfg) == "snom":
            fields = [("Incoming Call","in"),("Outgoing Call","out"),("On Connected","up"),("On Disconnected","end")]
        ttk.Label(f,text=text,wraplength=450,justify="left").grid(row=0,columnspan=2,pady=(0,12))
        def copy(url):
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
        for i,((key,event),name) in enumerate(zip(fields,LABELS),1):
            url = event_url(self.cfg,event)
            ttk.Label(f,text=f"{name}  ({key})").grid(row=i,column=0,sticky="w",pady=3)
            ttk.Button(f,text="URL kopieren",command=lambda u=url: copy(u)).grid(row=i,column=1)

    def test(self):
        if not self.servers:
            messagebox.showinfo("Testanruf","Bitte zuerst speichern und starten.")
            return
        text = simpledialog.askstring("Testanruf","Welche interne Testnummer soll das Tischtelefon jetzt wählen?")
        if text is None:
            return
        n = dial_number(text.strip())
        if not NUMBER.fullmatch(n):
            messagebox.showerror("Testanruf","Bitte eine gültige Rufnummer eingeben.")
            return
        phone = PlacetelDial(self.cfg) if self.cfg.get("zentral") else Yealink(self.cfg)
        def dial():
            try:
                phone.dial(n)
                self.report("Wählbefehl angenommen. Bitte Tischtelefon prüfen.")
            except Exception as exc:
                if isinstance(phone,PlacetelDial):
                    self.report("Placetel-Wahl fehlgeschlagen oder unbestätigt. " + (str(exc) if str(exc).startswith("Placetel antwortet") else "Telefon prüfen, bevor du erneut wählst."))
                    return
                self.report("Fernwahl fehlgeschlagen. Telefonfreigabe und Zertifikat prüfen. " + type(exc).__name__)
        threading.Thread(target=dial,daemon=True).start()

    def close(self):
        if self.servers and not messagebox.askyesno("CTI beenden?","Beenden unterbricht die Telefonanbindung. Mit Minimieren bleibt sie aktiv. Jetzt beenden?"):
            return
        self.stop()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    Window(root)
    root.mainloop()
