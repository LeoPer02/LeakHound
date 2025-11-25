import json
import os
import random
import re
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox

import pandas as pd
import requests
from faker import Faker

from LeakHound.NetTraceLogger import setup_logger

# Paths
UNMAPPED_FILE = 'path/to/unmapped.jsonl'
LABELED_FILE = 'path/to/labeled.jsonl'
STATE_FILE ='path/to/statefile.txt'
ENABLE_MODEL = False

# Purposes
PURPOSES = sorted([
    "['AD_DATA']", 'UNCLASSIFIED', "['ANALYTIC_DATA']", "['AD_TRACKING']",
    "['NETWORK_OPTIMIZATION']", "['INTERFACE_CUSTOMIZATION']", "['ANTI_FRAUD']",
    "['ANALYTIC_TRACKING']", "['MAP_NAVIGATION']", "['NEARBY_SEARCH']",
    "['AUTHENTICATION']", "['SIGNOUT_PERSONALIZATION']", "['THIRDPARTY_LOGIN']",
    "['LOCATION_BASED_CUSTOMIZATION']"
])

LABEL_EXAMPLES= {
    "ID.GENERALID" : {
        "['AD_TRACKING']": "Support ad targeting/evaluation",
        "['ANALYTIC_TRACKING']": "Avoid redundant device counting in marketing/Track device in analytics processes",
        "['ANTI_FRAUD']": "Enforce free content/advertisement limits",
        "['SIGNOUT_PERSONALIZATION']": "Personalize news for sign-out users",
        "['AUTHENTICATION']": "Relogin a user with a cookie"
    },
    "PHONE.DEVICE": {
        "['INTERFACE_CUSTOMIZATION']": "Customize the interface based on the resolution",
        "['AD_DATA']": "Collect data for ad personalization",
        "['ANALYTIC_DATA']": "Collect data for analytics"
    },
    "PHONE.NETWORK": {
        "['NETWORK_OPTIMIZATION']": "Download low resolution images when on LTE",
        "['AD_DATA']": "Collect data for ad personalization",
        "['ANALYTIC_DATA']": "Collect data for analytics"
    },
    "PERSONAL.ACCOUNT": {
        "['THIRDPARTY_LOGIN']": "Login through third party accounts",
        "['AD_DATA']": "Collect data for ad personalization",
        "['ANALYTIC_DATA']": "Collect data for analytics"
    },
    "SENSOR.LOCATION": {
        "['MAP_NAVIGATION']": "Find the user location in map apps",
        "['LOCATION_BASED_CUSTOMIZATION']": "Fetch local weather/radio information",
        "['NEARBY_SEARCH']": "Search nearby POIs/real states",
        "['AD_DATA']": "Collect data for ad personalization",
        "['ANALYTIC_DATA']": "Collect data for analytics"
    }

}

# If empty, all apps are allowed
# Use this to configure which apps to analyze
ALLOWED_APPS = [
    #"mobi.lockdown.weather"
    #"com.adeo.android.app"
    # "com.example.firstapp",
    # "com.example.secondapp",
]
ALL_TYPES = ["SENSOR.LOCATION", "PERSONAL.ACCOUNT", "PHONE.NETWORK", "ID.GENERALID", "PHONE.DEVICE"]
TYPE_FOCUS = ALL_TYPES#["SENSOR.LOCATION", "PERSONAL.ACCOUNT", "PHONE.NETWORK"]
TYPE_FOCUS = [typ for typ in ALL_TYPES if typ not in TYPE_FOCUS] # Later we filter the ones we dont want

import logging
logger = logging.getLogger(__name__)

class TraceClassifier:
    # Mapping of known app replacements
    # If the app package is different, otherwise make this empty
    changes = {
        #"air.co.id.netmediatama.NetMediatama": "np.com.nettv",
        #"com.g8n8.pregnancytracker": "com.pregnancy.babycenter.pregnancytracker.view",
        #"com.infan.travelbj": "com.tripit",
        #"com.girnarsoft.carbuddy": "com.carbuddy.app",
        #"com.emojifamily.emoji.keyboard.sticker.PinkHeart": "com.emojifamily.emoji.keyboard"
    }

    regex_patterns_val = {
        "latitude": re.compile(r"^(?P<lat>[+-]?(?:(?:[0-8]?\d\.\d+)|(?:90\.0+)))$", re.IGNORECASE),
        "longitude": re.compile(r"^(?P<lon>[+-]?(?:(?:1[0-7]\d\.\d+)|(?:[0-9]?\d\.\d+)|(?:180\.0+)))$", re.IGNORECASE),
        "coordinates": re.compile(
            r"^(?P<lat>[+-]?(?:(?:[0-8]?\d\.\d+)|(?:90\.0+))), ?(?P<lon>[+-]?(?:(?:1[0-7]\d\.\d+)|(?:[0-9]?\d\.\d+)|(?:180\.0+)))$",
            re.IGNORECASE),
        "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.IGNORECASE),
        "uuid": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                           re.IGNORECASE),
        "mac_address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", re.IGNORECASE),
        "ipv4": re.compile(
            r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            re.IGNORECASE),
        "ipv6": re.compile(r"^((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})$",
                           re.IGNORECASE),
        "phone": re.compile(r"^\+[1-9][0-9]{3,14}$", re.IGNORECASE)
    }

    def __init__(self, their_dataset: str, own_dataset: str, output_folder: str = "traceClassifierFiles"):
        if not os.path.exists(their_dataset):
            raise FileNotFoundError(f"File {their_dataset} does not exist")
        if not os.path.exists(own_dataset):
            raise FileNotFoundError(f"File {own_dataset} does not exist")

        self.their_dataset = pd.read_csv(their_dataset)
        self.their_dataset['purpose'] = self.their_dataset['purpose'].fillna("UNCLASSIFIED")
        self.their_dataset['type'] = self.their_dataset['type'].fillna("unknown")
        self.their_dataset['app'] = self.their_dataset['app'].apply(self.remap_app)
        self.their_dataset['map_key'] = list(zip(
            self.their_dataset.app,
            self.their_dataset.host,
            self.their_dataset.path,
            self.their_dataset.key
        ))
        self.purpose_map = self.their_dataset.dropna(subset=["purpose"])\
                                     .drop_duplicates("map_key")\
                                     .set_index("map_key")["purpose"].to_dict()

        self.own_dataset_path = own_dataset
        self.mapped_output = os.path.join(output_folder, "mapped.jsonl")
        self.manual_labeled_output = LABELED_FILE
        self.mapped_count = 0
        self.mapped_value_count = {}
        self.unmapped = set()

        os.makedirs(output_folder, exist_ok=True)
        open(UNMAPPED_FILE, 'w').close()

    def remap_app(self, app_name: str) -> str:
        return self.changes.get(app_name, app_name)

    def __regex_checks(self, val):
        return [name for name, pattern in self.regex_patterns_val.items() if pattern.search(val)]

    def _stream_records(self, fin):
        buffer = ''
        depth = 0
        in_string = False
        escape = False

        for line in fin:
            for char in line:
                buffer += char
                if char == '"' and not escape:
                    in_string = not in_string
                if not in_string:
                    if char == '{': depth += 1
                    elif char == '}': depth -= 1
                escape = (char == '\\' and not escape)
                if depth == 0 and buffer.strip():
                    text = buffer.strip()
                    buffer = ''
                    yield text
        if buffer.strip():
            yield buffer.strip()

    def map_labeled_entries(self):
        faker = Faker()
        logger.info("Mapping labeled entries")
        with open(self.own_dataset_path, 'r') as fin, Path(self.mapped_output).open('w') as fout:
            for raw in self._stream_records(fin):
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse record: {e}\nRecord: {raw}")
                    continue

                if not isinstance(record, dict):
                    logger.warning(f"Skipping non-dict record: {record!r}")
                    continue
                if 'device_info' in record:
                    continue

                app = self.remap_app(record.get("app") or "")
                host = record.get("host") or ""
                path = record.get("path") or ""
                if isinstance(path, list):
                    path = "/" + "/".join(path)

                for kvp in record.get("data", []):
                    key = kvp.get("key")
                    if not key:
                        #logger.debug(f"Skipping KVP missing key: {kvp}")
                        continue

                    for match in self.__regex_checks(str(kvp.get('val', ""))):
                        if match == 'ipv4': kvp['val'] = faker.ipv4_public()
                        elif match == 'ipv6': kvp['val'] = faker.ipv6()
                        elif match == 'latitude': kvp['val'] = faker.latitude()
                        elif match == 'longitude': kvp['val'] = faker.longitude()
                        elif match == 'coordinates':
                            kvp['val'] = f"{faker.latitude()},{faker.longitude()}"
                        elif match == 'mac_address': kvp['val'] = faker.mac_address()
                        elif match == 'uuid': kvp['val'] = faker.uuid4()

                    lookup = (app, host, path, key)
                    if any(not part for part in lookup):
                        logger.warning(f"Incomplete lookup: {lookup}")
                        continue

                    purpose = self.purpose_map.get(lookup)
                    if purpose is None:
                        self.unmapped.add(lookup)
                    else:
                        self.mapped_count += 1
                        self.mapped_value_count.setdefault(purpose, 0)
                        self.mapped_value_count[purpose] += 1
                        kvp['purpose'] = purpose

                fout.write(json.dumps(record, default=str) + '\n')

        with open(UNMAPPED_FILE, 'w') as uf:
            for app, host, path, key in self.unmapped:
                uf.write(json.dumps({ 'app': app, 'host': host, 'path': path, 'key': key }, default=str) + '\n')

        logger.info(f"Mapped: {self.mapped_count}")
        logger.info(f"Counts: {self.mapped_value_count}")
        logger.info(f"Unmapped: {len(self.unmapped)} entries written to {UNMAPPED_FILE}")

# This is an UI for the classification, kind of broken, do not recommend using it
class KVPLabeler(tk.Tk):
    def __init__(self, unmapped_set, dataset_path, model_url: str = "http://localhost:11434"):
        super().__init__()
        self.title("KVP Purpose Labeler")
        self.configure(bg="#2e2e2e")
        self.attributes('-fullscreen', True)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.model_url = model_url

        # for the new skip‑by‑host/path
        self.skipped_hostpaths = set()
        # Control buttons (minimize, close, skip app, skip host/path)
        btn_frame = tk.Frame(self, bg="#2e2e2e")
        btn_frame.place(relx=0.75, rely=0.02, relwidth=0.23, relheight=0.05)
        tk.Button(btn_frame, text="—", command=self.iconify, bg="#444", fg="#f5f5f5",
                  bd=0, font=("Consolas", 16), activebackground="#666").pack(side='left', expand=True, padx=5)
        tk.Button(btn_frame, text="✕", command=self.on_close, bg="#444", fg="#f5f5f5",
                  bd=0, font=("Consolas", 16, 'bold'), activebackground="#666").pack(side='left', expand=True, padx=5)

        self.dataset_path = dataset_path
        self.unmapped = unmapped_set
        self.entries = []

        # load & filter entries by ALLOWED_APPS
        with open(self.dataset_path) as f:
            current_info = None
            for line in f:

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    #logger.warning(f"JSON decode error: {e}")
                    #logger.warning(f"Offending line: {line.strip()}")
                    continue
                if 'device_info' in record:
                    current_info = record.copy()
                else:
                    try:
                        app = record.get('app')
                    except Exception as e:
                        logger.debug(f"Error getting app {record}: {e}")
                        continue
                    # if whitelist is non-empty, skip apps not in ALLOWED_APPS
                    if ALLOWED_APPS and app not in ALLOWED_APPS:
                        continue

                    host = record.get('host')
                    path = record.get('path')
                    callstack = record.get('callstack', []) or ["NO CALLSTACK"]
                    if isinstance(path, list):
                        path = '/' + '/'.join(path)
                    info_base = current_info.copy()
                    info_base.update({'app': app, 'host': host, 'path': path})
                    for kvp in record.get('data', []):
                        key = kvp.get('key')
                        if (app, host, path, key) in self.unmapped:
                            kvp_copy = kvp.copy()
                            kvp_copy['callstack'] = callstack
                            self.entries.append({'info': info_base.copy(), 'kvp': kvp_copy})

        # load already‑labeled set
        self.labeled = set()
        if os.path.exists(LABELED_FILE):
            with open(LABELED_FILE, "r") as lf:
                for line in lf:
                    rec = json.loads(line)
                    if 'device_info' not in rec:
                        self.labeled.add((rec['app'], rec['host'], rec['path'], rec['key']))

        self.todo = [
            e for e in self.entries
            if (e['info']['app'], e['info']['host'], e['info']['path'], e['kvp']['key']) not in self.labeled
        ]
        logger.info(f"Found {len(self.todo)} items to label (unmapped_set size: {len(self.unmapped)})")

        self.index = 0
        self.skipped_apps = set()
        self.state_file = STATE_FILE
        if os.path.exists(self.state_file):
            with open(self.state_file) as sf:
                state = json.load(sf)
                self.index = state.get("index", 0)

        self.header_written = set()

        # UI setup
        self.setup_styles()
        self.build_ui()
        self.load_current()

    def check_model_status(self) -> bool:
        """
        Check if the model is up by sending a GET request to the health check endpoint.

        Args:
            url (str): The URL of the model's health check endpoint.

        Returns:
            bool: True if the model is up, False otherwise.
        """
        try:
            resp = requests.get(f"{self.model_url}")
            return resp.status_code == 200
        except requests.exceptions.RequestException as e:
            print(f"Error checking model status: {e}")
            return False

    def send_prompt(self, prompt_data) -> str | None:
        """
        Send a prompt to the model with a specific wrapper format.

        Args:
            url (str): The URL of the model's generate endpoint.
            prompt_data (dict): A dictionary containing the data.

        Returns:
            str: The generated response from the model.
        """
        # Create the wrapper content

        # Send a prompt to an LLM to get a "second opinion". Might catch something I dont
        prompt = {
            "prompt": "Classify the following data (all keys belong to the same target) based on the labels provided."
                      f"The only labels allowed are {PURPOSES}."
                      "The callstack is what triggered the network request."
                      "Provide a small justification for the classification."
                      "The possible labels for a given type can be found in \"label_examples\"."
                      "Examples for each label are provided in \"label_examples\""
                      "UNCLASSIFIED in the fallback when unsure for all labels.",
            "label_examples": LABEL_EXAMPLES,
            "limitations": "Only one label allowed. Justification must be at max 100 words.",
            "format": "label\n\njustification",
            "data": prompt_data

        }

        wrapper_content = {
            "model": "gemma3:12b",  # Specify the model name
            "prompt": json.dumps(prompt),
            "stream": False
        }

        headers = {
            "Content-Type": "application/json"
        }

        #logger.debug(f"Prompt: {json.dumps(wrapper_content)}")
        try:
            response = requests.post(f"{self.model_url}/api/generate",
                headers = headers,
                data = json.dumps(wrapper_content)
            )
            response.raise_for_status()  # Raise an error for bad responses
            return json.loads(json.dumps(response.json())).get('response', "")  # Adjust this based on the actual response structure
        except requests.exceptions.RequestException as e:
            print(f"Error sending prompt: {e}")
            return None

    def setup_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background='#2e2e2e')
        style.configure('TLabel', background='#2e2e2e', foreground='#f5f5f5', font=("Consolas", 12))
        style.configure('TButton', background='#444', foreground='#f5f5f5', font=("Consolas", 12))
        style.map('TButton', background=[('active','#666')])
        style.configure('TRadiobutton', background='#2e2e2e', foreground='#f5f5f5', font=("Consolas", 10))

    def build_ui(self):
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        wrap_px = int(screen_w * 0.4)

        # top labels
        for text, attr in [('App:', 'app_label'), ('Host:', 'host_label'), ('Path:', 'path_label')]:
            frame = ttk.Frame(self, padding=(10,5,10,0))
            frame.pack(side='top', fill='x')
            lbl = ttk.Label(frame, text=text, wraplength=wrap_px, justify='left')
            lbl.pack(side='left', anchor='w')
            setattr(self, attr, lbl)

        # main content frames...
        content = ttk.Frame(self, padding=10)
        content.pack(fill='both', expand=True)
        # left (KVP)
        left = ttk.Frame(content)
        left.pack(side='left', fill='y', padx=(0,5))
        self.kvp_text = tk.Text(left, width=30, height=20, bg='#1e1e1e', fg='#f5f5f5', font=('Consolas',10))
        self.kvp_text.pack(fill='both', expand=True)
        # middle (info)
        mid = ttk.Frame(content)
        mid.pack(side='left', fill='both', expand=True, padx=5)
        self.info_text = tk.Text(mid, width=30, height=20, bg='#1e1e1e', fg='#f5f5f5', font=('Consolas',10))
        self.info_text.pack(fill='both', expand=True)
        # right (callstack)
        right = ttk.Frame(content)
        right.pack(side='left', fill='both', expand=True, padx=(5,0))
        self.call_text = tk.Text(right, width=30, height=20, bg='#1e1e1e', fg='#f5f5f5', font=('Consolas',10))
        self.call_text.pack(fill='both', expand=True)

        suggest_frame = ttk.Frame(content)
        suggest_frame.pack(side='left', fill='both', expand=True, padx=(5, 0))
        ttk.Label(suggest_frame, text="ℹ️ Model Suggestion:", font=("Consolas", 12, "italic")).pack(anchor='w')
        self.suggest_text = tk.Text(suggest_frame, width=30, height=20,
                                bg = '#1e1e1e', fg = '#aaffaa',
                                font = ('Consolas', 10), state = 'disabled')
        self.suggest_text.pack(fill='both', expand=True)

        # bottom controls
        bottom = ttk.Frame(self, padding=(10,5))
        bottom.pack(side='bottom', fill='x')
        bottom2 = ttk.Frame(self, padding=(10,5))
        bottom2.pack(side='bottom', fill='x')
        self.purpose_var = tk.StringVar(value='UNCLASSIFIED')
        for idx, p in enumerate(PURPOSES):
            container = bottom if idx < 7 else bottom2
            ttk.Radiobutton(container, text=p, variable=self.purpose_var, value=p).pack(side='left', padx=2)

        ln = ttk.Frame(self, padding=(10,5))
        ln.pack(side='bottom', fill='x')
        self.gplay = ttk.Label(ln, text='Google Play', foreground='lightblue', cursor='hand2')
        self.gplay.pack(side='left', padx=8)
        self.apkpure = ttk.Label(ln, text='APKPure', foreground='lightblue', cursor='hand2')
        self.apkpure.pack(side='left', padx=8)

        nav = ttk.Frame(ln)
        nav.pack(side='right')
        ttk.Button(nav, text='Previous', command=self.prev).pack(side='left', padx=4)
        ttk.Button(nav, text='Save & Next', command=self.save_next).pack(side='left', padx=4)
        ttk.Button(nav, text='Reset Skipped', command=self.reset_skipped).pack(side='left', padx=4)
        ttk.Button(nav, text="Skip App", command=self.skip_app).pack(side='left', expand=True, padx=5)
        ttk.Button(nav, text="Skip Host/Path", command=self.skip_hostpath).pack(side='left', expand=True, padx=5)

    def load_current(self):
        if not self.todo:
            messagebox.showinfo("Done", "All entries have been labeled.")
            return

        # skip undesirable types or hostpaths
        start = self.index
        while True:
            e = self.todo[self.index]
            kvp = e['kvp']
            t = kvp.get('type')
            hp = (e['info']['host'], e['info']['path'])
            ignore = []
            # ignore = ['unknown','INSUFFICIENT.INSUFFICIENT', 'NONPRIVACY.NONPRIVACY']
            # ignore.extend(TYPE_FOCUS)
            if ignore and t in ignore or hp in self.skipped_hostpaths:
                self.index = (self.index + 1) % len(self.todo)
                if self.index == start:
                    messagebox.showinfo("Done", "No more valid entries.")
                    return
                continue
            break

        e = self.todo[self.index]
        info, kvp = e['info'], e['kvp']
        self.app_label.config(text=f"App: {info['app']}")
        self.host_label.config(text=f"Host: {info['host']}")
        self.path_label.config(text=f"Path: {info['path']}")
        self.kvp_text.delete('1.0','end')
        for k,v in kvp.items():
            if k!='callstack':
                self.kvp_text.insert('end', f"{k}: {v}\n")
        self.info_text.delete('1.0','end')
        rel = {k:info[k] for k in ['device_info','location','content_query'] if k in info}
        self.info_text.insert('end', json.dumps(rel,indent=2))
        self.call_text.delete('1.0','end')
        for frm in kvp.get('callstack',[]):
            self.call_text.insert('end',frm+"\n")

        # ── NEW: get model suggestion ─────────────────────────────
        # Build the data payload exactly as TraceClassifier expects:
        payload = {
            "app": info['app'],
            "host": info['host'],
            "path": info['path'],
            "key": kvp['key'],
            "val": kvp.get('val'),
            "type": kvp.get('type'),
            "callstack": kvp.get('callstack', []),
            #"device_info": info.get('device_info', [])
        }
        suggestion = ""



        try:
            if ENABLE_MODEL and self.check_model_status():
                suggestion = self.send_prompt(payload) or ""
        except Exception as e:
            # silently ignore any model‑call error
            logger.warning(f"Model suggestion failed: {e}")

        # Display (or clear) the suggestion text box
        self.suggest_text.configure(state='normal')
        self.suggest_text.delete('1.0', 'end')
        if suggestion:
            self.suggest_text.insert('end', suggestion)
        self.suggest_text.configure(state='disabled')

        # bind links
        gp = f'https://play.google.com/store/apps/details?id={info["app"]}&hl=en'
        ap = f'https://apkpure.net/id/net/{info["app"]}'
        self.gplay.bind('<Button-1>', lambda e: os.system(f'start {gp}'))
        self.apkpure.bind('<Button-1>', lambda e: os.system(f'start {ap}'))
        self.purpose_var.set('UNCLASSIFIED')

    def save_state(self):
        with open(self.state_file,'w') as sf:
            json.dump({"index":self.index}, sf)

    def save_next(self):
        if not self.todo: return
        e = self.todo[self.index]
        info,kvp = e['info'],e['kvp']
        hp = (info['host'], info['path'])

        # if type undesired or hostpath skipped, just advance
        ignore = []
        # ignore = ['unknown','INSUFFICIENT.INSUFFICIENT', 'NONPRIVACY.NONPRIVACY']
        # ignore.extend(TYPE_FOCUS)
        if kvp.get('type') in ignore or hp in self.skipped_hostpaths:
            self.index = (self.index+1)%len(self.todo)
            self.save_state(); self.load_current()
            return

        keyid = (info['app'],info['host'],info['path'],kvp['key'])
        if keyid in self.labeled: return

        if info['app'] not in self.header_written:
            hdr = {
              'app':info['app'],
              'device_info':info.get('device_info',{}),
              'location':info.get('location',[]),
              'content_query':info.get('content_query',[])
            }
            with open(LABELED_FILE,'a') as lf:
                lf.write(json.dumps(hdr)+"\n")
            self.header_written.add(info['app'])

        ln = {
          'app':info['app'],'host':info['host'],'path':info['path'],
          'key':kvp['key'],'val':kvp.get('val'),
          'type':kvp.get('type'),'purpose':self.purpose_var.get(),
          'callstack':kvp.get('callstack')
        }
        with open(LABELED_FILE,'a') as lf:
            lf.write(json.dumps(ln)+"\n")

        self.labeled.add(keyid)
        # remove it from todo
        self.todo = [x for x in self.todo if (x['info']['app'],x['info']['host'],x['info']['path'],x['kvp']['key']) not in self.labeled]
        logger.info(f"Found {len(self.todo)} items to label (unmapped_set size: {len(self.unmapped)})")

        if self.todo:
            self.index %= len(self.todo)
        self.save_state()
        self.load_current()

    def skip_app(self):
        if not self.todo: return
        current_app = self.todo[self.index]['info']['app']
        self.skipped_apps.add(current_app)
        start = self.index
        while True:
            self.index = (self.index+1)%len(self.todo)
            if self.todo[self.index]['info']['app'] not in self.skipped_apps or self.index==start:
                break
        self.save_state()
        self.load_current()

    def skip_hostpath(self):
        """Skip all entries sharing this host & path."""
        if not self.todo: return
        info = self.todo[self.index]['info']
        hp = (info['host'], info['path'])
        self.skipped_hostpaths.add(hp)
        # advance to next not sharing same host/path
        start = self.index
        while True:
            self.index = (self.index+1)%len(self.todo)
            hi,pa = self.todo[self.index]['info']['host'], self.todo[self.index]['info']['path']
            if (hi,pa) not in self.skipped_hostpaths or self.index==start:
                break
        self.save_state()
        self.load_current()

    def prev(self):
        if not self.todo: return
        self.index = (self.index-1)%len(self.todo)
        self.save_state()
        self.load_current()

    def reset_skipped(self):
        self.skipped_apps.clear()
        self.skipped_hostpaths.clear()
        messagebox.showinfo("Reset", "Skipped apps and host/paths cleared.")
        self.load_current()

    def on_close(self):
        if messagebox.askokcancel('Quit','Exit?'):
            self.save_state()
            self.quit()

if __name__ == '__main__':
    logger = setup_logger(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), "netTraceCollector.log")
    classifier = TraceClassifier(
        "path/to/parsed_dataset.csv",
        "path/to/compiled_dataset.json",
        output_folder="traceClassifierFiles")
    classifier.map_labeled_entries()
    for lookup, purpose in classifier.purpose_map.items():
        app, host, path, key = lookup
    app = KVPLabeler(classifier.unmapped, classifier.own_dataset_path)
    app.mainloop()
