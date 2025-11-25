import base64
import json
import logging
import os.path
import re
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Any, Dict
from urllib.parse import urlparse

import spacy
from sklearn.feature_selection import mutual_info_classif

from LeakHound.NetTraceLogger import setup_logger

logger = logging.getLogger(__name__)


class ClusteringKeyValuePair(Enum):
    # Say that we get the following Key-Value Pairs in the clusterd entries (those from top domains which we join together)
    # id: 3
    # id: 10
    # id: 4

    # This will return
    # id: 3 10 4
    join_kvps = 1

    # This will return
    # id: 3
    discard_kvps = 2

    # This will return
    # id: 3
    # id: 10
    # id: 4
    keep_kvps = 3


class TraceParser:

    def __init__(self, output_folder: str, spacy_model_path: str = None,
                 kvps_action: ClusteringKeyValuePair = ClusteringKeyValuePair.keep_kvps):

        if not os.path.exists(output_folder):
            raise FileNotFoundError(f"Folder {output_folder} not found")

        self.output_folder = output_folder
        self.total_request_count: int = 0
        self.request_index: int = 0
        self.model = None

        # If we have:
        # id: 3
        # id: 2

        # then in the end we have
        self.kvps_action: ClusteringKeyValuePair = kvps_action
        if spacy_model_path and os.path.exists(spacy_model_path):
            logger.info("Loading Spacy model")
            self.model = spacy.load(spacy_model_path)

        self.top_domains = {
            "csi.gstatic.com": {
                "https://csi.gstatic.com/csi?network_coarse": re.compile(
                    r"^https://csi\.gstatic\.com/csi\?network_coarse.*"),
                "https://csi.gstatic.com/csi?aai": re.compile(r"^https://csi\.gstatic\.com/csi\?aai.*"),
                "https://csi.gstatic.com/csi?adapter": re.compile(r"^https://csi\.gstatic\.com/csi\?adapter.*"),
                "https://csi.gstatic.com/csi?task": re.compile(r"^https://csi\.gstatic\.com/csi\?task.*"),
                "https://csi.gstatic.com/csi?v": re.compile(r"^https://csi\.gstatic\.com/csi\?v.*"),
                "https://csi.gstatic.com/csi?s=gmob_sdk": re.compile(r"^https://csi\.gstatic\.com/csi\?s=gmob_sdk.*"),
                "https://csi.gstatic.com/csi?show_time": re.compile(r"^https://csi\.gstatic\.com/csi\?show_time.*"),
                "https://csi.gstatic.com/csi?seq_num": re.compile(r"^https://csi\.gstatic\.com/csi\?seq_num.*"),
                "https://csi.gstatic.com/csi?sc": re.compile(r"^https://csi\.gstatic\.com/csi\?sc.*"),
                "https://csi.gstatic.com/csi?msg": re.compile(r"^https://csi\.gstatic\.com/csi\?msg.*")
            },
            "pagead2.googlesyndication.com": {
                "https://pagead2.googlesyndication.com/pagead/gen": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pagead/gen.*"),
                "https://pagead2.googlesyndication.com/pagead/interaction": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pagead/interaction/.*"),
                "https://pagead2.googlesyndication.com/pagead/conversion": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pagead/conversion/.*"),
                "https://pagead2.googlesyndication.com/pagead/js": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pagead/js.*"),
                "https://pagead2.googlesyndication.com/pagead/managed": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pagead/managed.*"),
                "https://pagead2.googlesyndication.com/pcs/activeview": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pcs/activeview\?.*"),
                "https://pagead2.googlesyndication.com/pcs/view": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/pcs/view\?.*"),
                "https://pagead2.googlesyndication.com/p/": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/p/.*"),
                "https://pagead2.googlesyndication.com/ccm/collect": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/ccm/collect.*"),
                "https://pagead2.googlesyndication.com/omsdk/releases": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/omsdk/releases.*"),
                "https://pagead2.googlesyndication.com/favicon": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/favicon\.ico.*"),
                "https://pagead2.googlesyndication.com/bg/": re.compile(
                    r"^https://pagead2\.googlesyndication\.com/bg/.*")
            },
            "googleads.g.doubleclick.net": {
                "https://googleads.g.doubleclick.net/pagead/interaction": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/pagead/interaction.*"),
                "https://googleads.g.doubleclick.net/pagead/adview": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/pagead/adview.*"),
                "https://googleads.g.doubleclick.net/dbm/ad": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/dbm/ad.*"),
                "https://googleads.g.doubleclick.net/xbbe/pixel": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/xbbe/pixel.*"),
                "https://googleads.g.doubleclick.net/ads/preferences/getcookie": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/ads/preferences/getcookie.*"),
                "https://googleads.g.doubleclick.net/aclk/": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/aclk/.*"),
                "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/production": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/mads/static/mad/sdk/native/production.*"),
                "https://googleads.g.doubleclick.net/getconfig/pubsetting": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/getconfig/pubsetting.*"),
                "https://googleads.g.doubleclick.net/pagead/viewthroughconversion": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/pagead/viewthroughconversion.*"),
                "https://googleads.g.doubleclick.net/pagead/aclk/": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/pagead/aclk/.*"),
                "https://googleads.g.doubleclick.net/pagead/images": re.compile(
                    r"^https://googleads\.g\.doubleclick\.net/pagead/images.*")
            },
            "fls-na.amazon.com": {
                "https://fls-na.amazon.com/<num1>/batch/<num2>/OP/<FIRSTID>:<UUID>:<SECONDID>$": re.compile(
                    r"^https://fls-na\.amazon\.com/\d+/batch/\d+/OP/[^:]+:[^:]+:[^$]+"),
                "https://fls-eu.amazon.com/<num1/batch/<num2>/OP/<FIRSTID>:<UUID>:<SECONDID>$": re.compile(
                    r"^https://fls-eu\.amazon\.com/\d+/batch/\d+/OP/[^:]+:[^:]+:[^$]+"),
                "https://fls-na.amazon.com/<num1>/remote-weblab-triggers/<num2>/OE/<FIRSTID>:<UUID>:<SECONDID>": re.compile(
                    r"^https://fls-na\.amazon\.com/\d+/remote-weblab-triggers/\d+/OE/[^:]+:[^:]+:[^$]+"),
                "https://fls-eu.amazon.com/<num1>/remote-weblab-triggers/<num2>/OE/<FIRSTID>:<UUID>:<SECONDID>": re.compile(
                    r"^https://fls-eu\.amazon\.com/\d+/remote-weblab-triggers/\d+/OE/[^:]+:[^:]+:[^$]+"),
                "https://fls-na.amazon.com/<num1>/action-impressions/<num2>/OP/mshop/action/msh_": re.compile(
                    r"^https://fls-na\.amazon\.com/\d+/action-impressions/\d+/OP/mshop/action/msh_.*"),
                "https://fls-eu.amazon.com/<num1>/action-impressions/<num2>/OP/mshop/action/msh_": re.compile(
                    r"^https://fls-eu\.amazon\.com/\d+/action-impressions/\d+/OP/mshop/action/msh_.*")
            },
            "m.media-amazon.com": {
                "https://m.media-amazon.com/images/I/": re.compile(r"^https://m\.media-amazon\.com/images/I/.*"),
                "https://m.media-amazon.com/images/S/": re.compile(r"^https://m\.media-amazon\.com/images/S/.*"),
                "https://m.media-amazon.com/images/G/": re.compile(r"^https://m\.media-amazon\.com/images/G/.*")
            },
            "graph.facebook.com": {
                "https://graph.facebook.com/v<version>/app/model_asset": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/app/model_asset.*"),
                "https://graph.facebook.com/v<version>/app/mobile_sdk_gk": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/app/mobile_sdk_gk.*"),
                "https://graph.facebook.com/v<version>/app": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/app\?.*"),
                "https://graph.facebook.com/v<version>/<UUID>/activities": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/\d+/activities.*"),
                "https://graph.facebook.com/v<version>/<UUID>/button_auto_detection_device_selection": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/\d+/button_auto_detection_device_selection\??.*"),
                "https://graph.facebook.com/v<version>/<UUID>/mobile_sdk_gk": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/\d+/mobile_sdk_gk\?.*"),
                "https://graph.facebook.com/v<version>/<UUID>": re.compile(
                    r"^https://graph\.facebook\.com/v\d+\.\d+/\d+.*")
            }
        }

    def run(self):
        logger.info("Compiling dataset...")
        self.total_request_count = 0
        subfolders = [
            os.path.join(self.output_folder, name)
            for name in os.listdir(self.output_folder)
            if os.path.isdir(os.path.join(self.output_folder, name))
        ]

        open('path/to/compiled_dataset.json', 'w').close()
        open('path/to/parsed_dataset.json', 'w').close()

        # Create a ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=os.cpu_count() - 2) as executor:
            # Submit tasks to the executor
            futures = [executor.submit(self.__get_individual_folders, subfolder) for subfolder in subfolders]

            # Retrieve results as they complete
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error for future: {future}: {e}")

        file_list = [f"traceParserFiles\\{os.path.basename(subfolder).replace("_", ".")}.json" for subfolder in
                     subfolders]
        with open('path/to/compiled_dataset.json', 'w', encoding='utf-8') as wfd:
            for fname in file_list:
                with open(fname, 'r', encoding='utf-8') as fd:
                    for line in fd:
                        # remove any existing trailing newline
                        clean = line.rstrip('\n')
                        # write it back with exactly one newline
                        wfd.write(clean + '\n')

        logger.info(f"Finished Compiling dataset at {self.output_folder}")
        logger.info(f"A total of {self.total_request_count} network traces were registered (after preprocessing)")

    @staticmethod
    def __get_frida_traces(folder: str):
        if not os.path.exists(folder):
            logger.error(f"Folder provided {folder} does not exist")
            return []

        frida_traces: dict[str, list] = {}

        keys_to_collect = ['thread', 'socket', 'location_hook', 'content_query']

        for key in keys_to_collect:
            frida_traces[key] = []

        for root, _, files in os.walk(folder):
            for filename in files:
                full_path = os.path.join(root, filename)
                if filename == "frida_traces.json":
                    with open(full_path, "r", encoding='utf-8') as traces:
                        data = json.load(traces)
                        for key in keys_to_collect:
                            if key in data:
                                vals = data[key]
                                for val in vals:
                                    if isinstance(val, list):
                                        frida_traces[key].extend(val)
                                    else:
                                        frida_traces[key].append(val)
                else:
                    continue

        return frida_traces

    @staticmethod
    def __get_device_info(folder: str):
        if not os.path.exists(folder):
            logger.error(f"Folder provided {folder} does not exist")
            return []

        for root, _, files in os.walk(folder):
            for filename in files:
                full_path = os.path.join(root, filename)
                if filename == "device_info.json":
                    with open(full_path, "r", encoding='utf-8') as traces:
                        data = json.load(traces)
                        if 'device_info' in data:
                            return data['device_info']

        return None

    @staticmethod
    def __get_network_info(folder: str):
        if not os.path.exists(folder):
            logger.error(f"Folder provided {folder} does not exist")
            return []

        network_traces = []

        for root, _, files in os.walk(folder):
            for filename in files:
                full_path = os.path.join(root, filename)
                if filename == "network_traces.json":
                    with open(full_path, "r", encoding='utf-8') as traces:
                        data = json.load(traces)
                        if 'traces' in data:
                            for trace in data.get('traces', []):
                                request = None
                                response = None
                                if 'request' in trace:
                                    request = trace['request']
                                if 'response' in trace:
                                    response = trace['response']

                                network_traces.append((request, response))

        return network_traces

    @staticmethod
    def __strip_trailer(call: str) -> str:
        """
        Remove any trailing '(...)'—for example '(Foo.java:123)' or any other
        parentheses content—at the end of the string.
        """
        return re.sub(r'\([^)]*\)$', '', call)

    def __compute_call_paths(self, app_name, info_per_app):

        frida_traces: dict[str, list] = info_per_app['frida_traces']
        if 'thread' not in frida_traces:
            logger.error("Threads not found in frida_traces")
            return None

        keys = ["parent_thread_name", "parent_thread_id", "parent_thread_group", "thread_name", "thread_id",
                "thread_group", "callStack"]
        mapping: dict[tuple[str, str, str], set[tuple[str, str, str]]] = {}
        callStacks: dict[tuple[str, str, str], list[str]] = {}
        for thread in frida_traces['thread']:
            if any(key not in thread for key in keys):
                continue
            if not thread:
                logger.debug("Thread is None")
                continue
            thread_id = thread.get('thread_id', "")
            parent_id = thread.get('parent_thread_id', "")
            thread_name = thread.get('thread_name', "")
            parent_thread_name = thread.get('parent_thread_name', "")
            thread_group = thread.get('thread_group', "")
            parent_thread_group = thread.get('parent_thread_group', "")
            callStack = thread.get('callStack', [])

            if (thread_id, thread_name, thread_group) not in mapping:
                mapping[(thread_id, thread_name, thread_group)] = set()

            if (thread_id, thread_name, thread_group) not in callStacks:
                callStacks[(thread_id, thread_name, thread_group)] = []

            mapping[(thread_id, thread_name, thread_group)].add((parent_id, parent_thread_name, parent_thread_group))
            callStacks[(thread_id, thread_name, thread_group)] = [self.__strip_trailer(call) for call in callStack]

        def get_all_upward_paths(parent_map: dict[tuple[str, str, str], set[tuple[str, str, str]]]) -> list[
            tuple[str, str, str]]:
            all_paths = []

            # Collect all nodes that appear as parents
            all_parents = set()
            for parents in parent_map.values():
                all_parents.update(parents)

            # Leaves are nodes that never appear as parents
            leaves = [node for node in parent_map if node not in all_parents]

            # Recursive DFS to walk upward from a node
            def walk_up(path: list[tuple[str, str, str]]):
                current = path[-1]
                if current not in parent_map or not parent_map[current]:
                    all_paths.append(path)
                    return
                for parent in parent_map[current]:
                    walk_up(path + [parent])

            # Walk from each leaf
            for leaf in leaves:
                walk_up([leaf])

            return all_paths

        return get_all_upward_paths(mapping), callStacks

    def __get_socket_callgraph(self, frida_traces: dict[str, list], sequences: list[tuple[str, str, str]],
                               callStacks: dict[tuple[str, str, str], list[str]]):
        if 'socket' not in frida_traces:
            logger.error("No socket in frida_traces")

        socket_mapping: dict[tuple[str, str, str], list[str]] = {}
        socket_thread_names: dict[tuple[str, str, str], list[str]] = {}

        for socket in frida_traces.get('socket', []):
            if socket is None:
                logger.debug("Socket is None")
                continue

            socket_host = socket.get('host', "")
            socket_port = socket.get('port', "")
            socket_timestamp = socket.get('timestamp', "")
            socket_thread_id = socket.get('thread_id', "")
            socket_thread_name = socket.get('thread_name', "")
            socket_thread_group = socket.get('thread_group', "")
            socket_callstack = [self.__strip_trailer(call) for call in socket.get('callStack', [])]

            thread = (socket_thread_id, socket_thread_name, socket_thread_group)

            for sequence in sequences:
                if thread in sequence:
                    index = sequence.index(thread)
                    path = sequence[index:]
                    socket_mapping[(socket_host, socket_port, socket_timestamp)] = socket_callstack
                    socket_thread_names[(socket_host, socket_port, socket_timestamp)] = []
                    for el in path:
                        socket_mapping[(socket_host, socket_port, socket_timestamp)].extend(callStacks.get(el, []))
                        socket_thread_names[(socket_host, socket_port, socket_timestamp)].append(el[1])

        return socket_mapping, socket_thread_names

    @staticmethod
    def __get_request_call_stack(frida_traces: dict[str, list], network_traces: list[(dict, dict)],
                                 socket_mapping: dict[tuple[str, str, str], list[str]],
                                 socket_thread_names: dict[tuple[str, str, str], list[str]]):

        if not 'socket' in frida_traces:
            logger.error("Socket not in frida_traces")
            return None

        network_mapping: dict[tuple[str, str], list[str]] = {}
        thread_names: dict[tuple[str, str], list[str]] = {}

        for network_trace in network_traces:
            request = network_trace[0]
            if request is None:
                # The json is malformed
                # logger.debug("request is None")
                continue
            request_url = request.get('real_url', "")
            request_timestamp = request.get('timestamp_start', "")
            request_ip = request.get('url', "")
            ip = urlparse(request_ip).hostname
            url = urlparse(request_url).hostname
            port = request.get('port', "")

            network_mapping[(request_url, request_timestamp)] = []

            # found = False

            for socket in frida_traces['socket']:
                if socket['host'] == f"{url}/{ip}:{port}" or socket['host'] == f"/{ip}:{port}":
                    socket_host = socket.get('host', "")
                    socket_port = socket.get('port', "")
                    socket_timestamp = socket.get('timestamp', "")
                    network_mapping[(request_url, request_timestamp)] = socket_mapping.get(
                        (socket_host, socket_port, socket_timestamp), [])
                    thread_names[(request_url, request_timestamp)] = socket_thread_names.get(
                        (socket_host, socket_port, socket_timestamp), [])
                    # logger.info(f"Found match for {request_url}")
                    # found = True

            # if not found:
            #     logger.warning(f"Did not found match for {request_url}")

        return network_mapping, thread_names

    def __get_location_call_stack(self, frida_traces: dict[str, list], sequences: list[tuple[str, str, str]],
                                  callStacks: dict[tuple[str, str, str], list[str]]):
        if not 'location_hook' in frida_traces:
            logger.error("location_hook not in frida_traces")
            return None

        location_call_stack_mapping: dict[tuple[str, str, str, str], list[str]] = {}
        location_thread_names: dict[tuple[str, str, str, str], list[str]] = {}

        for location in frida_traces.get('location_hook', []):
            location_timestamp = location.get('timestamp', "")
            location_longitude = location.get('longitude', "")
            location_latitude = location.get('latitude', "")
            location_method = location.get('method', "")
            location_thread_id = location.get('thread_id', "")
            location_thread_name = location.get('thread_name', "")
            location_thread_group = location.get('thread_group', "")
            location_callStack = [self.__strip_trailer(call) for call in location.get('callStack', [])]

            id = (location_method, location_longitude, location_latitude, location_timestamp)
            thread = (location_thread_id, location_thread_name, location_thread_group)

            for sequence in sequences:
                if thread in sequence:
                    index = sequence.index(thread)
                    path = sequence[index:]
                    location_call_stack_mapping[id] = location_callStack
                    location_thread_names[id] = []
                    for el in path:
                        location_call_stack_mapping.get(id, {}).extend(callStacks.get(el, []))
                        location_thread_names.get(id, {}).append(el[1])

        return location_call_stack_mapping, location_thread_names

    def __get_content_query_call_stack(self, frida_traces: dict[str, list], sequences: list[tuple[str, str, str]],
                                       callStacks: dict[tuple[str, str, str], list[str]]):
        if not 'content_query' in frida_traces:
            logger.error("content_query not in frida_traces")
            return None

        content_query_call_stack_mapping: dict[tuple[str, dict], list[str]] = {}
        content_query_thread_names: dict[tuple[str, dict], list[str]] = {}

        for query in frida_traces['content_query']:
            query_uri = query.get('uri', "")
            query_thread_id = query.get('thread_id', "")
            query_thread_name = query.get('thread_name', "")
            query_thread_group = query.get('thread_group', "")
            query_callstack = [self.__strip_trailer(call) for call in query.get('callStack', [])]

            id = (query_uri, query_thread_name)
            thread = (query_thread_id, query_thread_name, query_thread_group)

            for sequence in sequences:
                if thread in sequence:
                    index = sequence.index(thread)
                    path = sequence[index:]
                    content_query_call_stack_mapping[id] = query_callstack
                    content_query_thread_names[id] = []
                    for el in path:
                        content_query_call_stack_mapping.get(id, {}).extend(callStacks.get(el, []))
                        content_query_thread_names.get(id, {}).append(el[1])

        return content_query_call_stack_mapping, content_query_thread_names

    def __get_individual_folders(self, subfolder):
        info_per_app: dict[str, dict[str, list] | list]
        top_domain_request: dict[str, list[dict]] = {}

        folder_name = os.path.basename(subfolder).replace("_", ".")

        if os.path.exists(f"path/to/{folder_name}.json"):
            logger.info(f"File path/to/{folder_name} already exists")
        else:
            logger.info(f"Running Analysis for {folder_name}")
            open(f"path/to\\{folder_name}.json", "w").close()

        try:
            info_per_app = {'frida_traces': self.__get_frida_traces(subfolder),
                            'device_info': self.__get_device_info(subfolder),
                            'network_traces': self.__get_network_info(subfolder)}

            sequences, callStacks = self.__compute_call_paths(folder_name, info_per_app)
            socket_mapping: dict[tuple[str, str, str], list[str]] = {}
            socket_thread_names: dict[tuple[str, str, str], list[str]] = {}
            request_callstack_mapping: dict[tuple[str, str], list[str]] = {}
            request_thread_names: dict[tuple[str, str], list[str]] = {}
            location_callstack_mapping: dict[tuple[str, str, str, str], list[str]] = {}
            location_thread_names: dict[tuple[str, str, str, str], list[str]] = {}
            content_query_callstack_mapping: dict[tuple[str, dict], list[str]] = {}
            content_query_thread_names: dict[tuple[str, dict], list[str]] = {}
            try:
                socket_mapping, socket_thread_names = self.__get_socket_callgraph(info_per_app['frida_traces'],
                                                                                  sequences, callStacks)
            except Exception as e:
                logger.error(f"Error on socket mapping: {e}")
            try:
                request_callstack_mapping, request_thread_names = self.__get_request_call_stack(
                    info_per_app.get('frida_traces', {}), info_per_app.get('network_traces', []), socket_mapping,
                    socket_thread_names)
            except Exception as e:
                logger.error(f"Error on network traces: {e}")
            try:
                location_callstack_mapping, location_thread_names = self.__get_location_call_stack(
                    info_per_app.get('frida_traces', {}), sequences, callStacks)
            except Exception as e:
                logger.error(f"Error on location traces: {e}")
            try:
                content_query_callstack_mapping, content_query_thread_names = self.__get_content_query_call_stack(
                    info_per_app.get('frida_traces', {}), sequences, callStacks)
            except Exception as e:
                logger.error(f"Error on content traces: {e}")

            network_requests = []
            location_traces = []
            content_traces = []

            if request_callstack_mapping == {}:
                # logger.error("Failed to obtain request_callstack_mapping")
                return

            if location_callstack_mapping == {}:
                # logger.error("Failed to obtain location_callstack_mapping")
                pass

            if socket_mapping == {}:
                # logger.error("Failed to obtain socket_mapping")
                pass

            if content_query_callstack_mapping == {}:
                # logger.error("Failed to obtain content_query_callstack_mapping")
                pass

            for (network, _) in info_per_app.get('network_traces', []):
                if network is None:
                    continue
                host = urlparse(network.get('real_url', "")).hostname
                # If in the top dommain, collect for later clustering
                if host in self.top_domains:
                    # logger.debug(f"Found top_domain {host} for {network.get('real_url', "")}")
                    for name, rule in self.top_domains[host].items():
                        if re.match(rule, network.get('real_url', "")):
                            if name not in top_domain_request:
                                top_domain_request[name] = []

                            body: dict = self.__parse_kv_pairs(network.get("text", "")) if self.__is_json(
                                network.get('text', "")) else {}
                            queries = network.get('query', {})

                            top_domain_request[name].append({
                                'url': network.get('real_url', ""),
                                'method': network.get('method', ""),
                                'port': network.get('port', -1),
                                'cookies': network.get('cookies', {}),
                                'path': network.get('path_components', []),
                                'query': queries,
                                'trailers': network.get('trailers', {}),
                                'headers': network.get('headers', {}),
                                'timestamp': network.get('timestamp_start', ""),
                                'body': body,
                                'multipart_form': network.get('multipart_form', {}),
                                'thread_names': request_thread_names.get(
                                    (network.get('real_url', ""), network.get('timestamp_start', "")), []),
                                'callstack': request_callstack_mapping.get(
                                    (network.get('real_url', ""), network.get('timestamp_start', "")), [])

                            })

                else:
                    # Prefer JSON text if present, otherwise take the URL-encoded form dict
                    #### DEBUGGGGG #####
                    raw_text = network.get("text", "")
                    body = None
                    if raw_text:
                        body = self.__parse_kv_pairs(raw_text) if self.__is_json(raw_text) else {}

                    urlenconded = network.get("urlencoded_form", {})

                    if body is None:
                        body = {}

                    for key, val in urlenconded.items():
                        body[key] = val

                    multipart_form = network.get('multipart_form', {})

                    queries = network.get("query", {})

                    # skip truly empty payloads
                    if not body and not queries and not urlenconded and not multipart_form:
                        continue

                    network_requests.append({
                        'index': self.request_index,
                        'url': network.get('real_url', ""),
                        'method': network.get('method', ""),
                        'port': network.get('port', -1),
                        'cookies': network.get('cookies', {}),
                        'path': network.get('path_components', []),
                        'query': queries,
                        'trailers': network.get('trailers', {}),
                        'timestamp': network.get('timestamp_start', ""),
                        'body': body,
                        'multipart_form': multipart_form,
                        'thread_names': request_thread_names.get(
                            (network.get('real_url', ""), network.get('timestamp_start', "")), []),
                        'callstack': request_callstack_mapping.get(
                            (network.get('real_url', ""), network.get('timestamp_start', "")), [])

                    })
                    self.request_index += 1

            for location in info_per_app.get('frida_traces', {}).get('location_hook', []):
                location_traces.append({
                    'method': location.get('method', ""),
                    'latitude': location.get('latitude', ""),
                    'longitude': location.get('longitude', ""),
                    'timestamp': location.get('timestamp', ""),
                    'thread_name': location_thread_names.get((location.get('method', ""), location.get('longitude', ""),
                                                              location.get('latitude', ""),
                                                              location.get('timestamp', "")), []),
                    'callstack': location_callstack_mapping.get((location.get('method', ""),
                                                                 location.get('longitude', ""),
                                                                 location.get('latitude', ""),
                                                                 location.get('timestamp', "")),
                                                                []) if location_callstack_mapping != {} else []
                })

            for query in info_per_app.get('frida_traces', {}).get('content_query', []):
                content_traces.append({
                    'uri': query.get('uri', ""),
                    'data': query.get('data', []),
                    'thread_name': content_query_thread_names.get((query.get('uri', ""), query.get('thread_name', {})),
                                                                  []),
                    'callstack': content_query_callstack_mapping.get(
                        (query.get('uri', ""), query.get('thread_name', {})), [])
                })

            # Clustering of top domains to avoid bias
            for host, reqs in top_domain_request.items():
                # Use defaultdict(set) to collect unique values per key
                cookies = defaultdict(set)
                query = defaultdict(set)
                body = defaultdict(set)
                trailers = defaultdict(set)
                multipart_form = defaultdict(set)
                thread_names = set()
                callStack = set()
                method = ""
                port = ""
                timestamp = ""

                for req in reqs:
                    method = req.get('method', method)
                    port = req.get('port', port)
                    timestamp = req.get('timestamp', timestamp)

                    # Merge cookie KVPs
                    for key, val in req.get('cookies', {}).items():
                        cookies[key].add(val)

                    # Merge query KVPs
                    for key, val in req.get('query', {}).items():
                        query[key].add(val)

                    # Merge body KVPs
                    for key, val in req.get('body', {}).items():
                        body[key].add(val)

                    # Merge trailer KVPs
                    for key, val in req.get('trailers', {}).items():
                        trailers[key].add(val)

                    for key, val in req.get('multipart_form', {}).items():
                        key = str(key)
                        val = str(val)
                        if self.__is_json(val):
                            kvps = self.__parse_kv_pairs(val)
                            for key, val in kvps.items():
                                multipart_form[key].add(val)
                        else:
                            multipart_form[key].add(val)

                    # Collect threads and callstacks
                    thread_names.update(req.get('thread_names', []))
                    callStack.update(req.get('callstack', []))

                # Before appending, turn each set into a semicolon-joined string
                def serialize(d: dict[str, set[Any]]) -> dict[str, str]:
                    return {
                        k: ";".join(sorted(map(str, v)))
                        for k, v in d.items()
                        if v
                    }

                try:
                    network_requests.append({
                        'index': self.request_index,

                        'url': host,
                        'path': [segment for segment in urlparse(host).path.strip("/").split("/") if segment],
                        'method': method,
                        'port': port,
                        'timestamp': timestamp,

                        'cookies': serialize(cookies),
                        'query': serialize(query),
                        'body': serialize(body),
                        'multipart_form': serialize(multipart_form),
                        'trailers': serialize(trailers),
                        'thread_names': list(thread_names),
                        'callstack': list(callStack),

                        'clustered': True,
                    })
                    self.request_index += 1
                except Exception as e:
                    logger.error(f"Failed to append top domain request {host} because: {e}")

            self.total_request_count += len(network_requests)

            if self.model is None:
                logger.warning(
                    "Spacy model not found, this will make it impossible to classify the purpose of key-values")
                logger.warning(
                    "Instead of the type-labeled dataset, a dataset with all per-request information will be created")
                data = {
                    'app': folder_name,
                    'device_info': info_per_app.get('device_info', []),
                    'network_traces': network_requests,
                    'location': location_traces,
                    'content_query': content_traces
                }

                try:
                    with open(f"traceParserFiles/{folder_name}.json", "a") as f:
                        json.dump(data, f)
                except Exception as e:
                    print(f"Failed to write to file for app {folder_name} because: {e}")

            else:

                try:

                    data = {
                        'app': folder_name,
                        'device_info': info_per_app.get('device_info', []),
                        'location': location_traces,
                        'content_query': content_traces
                    }

                    # logger.warning(f"Writting to : {folder_name}.json")
                    try:
                        with open(f"traceParserFiles\\{folder_name}.json", "a") as f:
                            json.dump(data, f)
                            f.write("\n")
                    except Exception as e:
                        logger.error(f"Error while writting: {e}")
                    for req in network_requests:

                        parsed_dataset = {
                            'data': defaultdict(set)
                        }

                        for source in ('cookies', 'query', 'body', 'multipart_form'):
                            for key, val in req.get(source, {}).items():
                                if key not in parsed_dataset['data']:
                                    parsed_dataset['data'][key] = set()
                                parsed_dataset['data'][key].add(val)

                        list_of_labeled_type: list[dict] = []
                        # logger.debug(f"For {folder_name} <{req.get("url", "")}> we get:\n{parsed_dataset['data']}")

                        # Convert sets to semicolon-separated strings and save them
                        for key, val_set in parsed_dataset['data'].items():
                            # Join all KVPs into one
                            if self.kvps_action == ClusteringKeyValuePair.join_kvps:
                                val = ' '.join(str(v) for v in val_set)
                                text = f"{key} = {val}"
                                doc = self.model(text)
                                label = doc.cats
                                predicted_label = max(label, key=label.get)

                            # Just get the first one
                            elif self.kvps_action == ClusteringKeyValuePair.discard_kvps:
                                val = list(val_set)[0]
                                if val is None:
                                    val = ""
                                text = f"{key} = {val}"
                                doc = self.model(text)
                                label = doc.cats
                                predicted_label = max(label, key=label.get)

                            # Return all of them (discarding complete duplicates)
                            else:
                                for val in val_set:
                                    text = f"{key} = {val}"
                                    doc = self.model(text)
                                    label = doc.cats
                                    predicted_label = max(label, key=label.get)
                                    labeled_type = {'key': key, 'val': val, 'type': predicted_label}
                                    list_of_labeled_type.append(labeled_type)
                                continue
                            labeled_type = {'key': key, 'val': val, 'type': predicted_label}

                            list_of_labeled_type.append(labeled_type)

                        data = {
                            'app': folder_name,
                            'host': urlparse(req.get('url', "")).hostname,
                            'path': "/" + "/".join(req.get('path', [])),
                            'data': list_of_labeled_type,
                            'callstack': req.get('callstack', "")

                        }

                        # logger.warning(f"Writting to : {folder_name}.json")
                        try:
                            with open(f"path/to\\{folder_name}.json", "a") as f:
                                json.dump(data, f)
                                f.write("\n")
                        except Exception as e:
                            logger.error(f"Error while writting: {e}")
                except Exception as e:
                    logger.error(f"Error while processing data: {e}")

            logger.info(f"[*] Compiled {folder_name}")
        except Exception as e:
            logger.error(f"Failed to process {folder_name} because: {e}")

    @staticmethod
    def __try_decode_base64(s: str) -> str:
        """If s is valid Base64, decode it; otherwise return original."""
        try:
            decoded = base64.b64decode(s, validate=True)
            # Try to decode bytes to text
            return decoded.decode('utf-8')
        except Exception:
            return s

    def __is_json(self, s: str) -> bool:
        """Return True if s (or its Base64 decode) is valid JSON."""
        text = self.__try_decode_base64(s)
        try:
            json.loads(text)
            return True
        except Exception:
            return False

    @staticmethod
    def __load_maybe_quoted_json(s):
        # If it looks like it's wrapped in quotes with backslashes, unwrap it
        if s.startswith('"') and s.endswith('"'):
            # Remove the leading and trailing quote, then un-escape
            s = bytes(s[1:-1], "utf-8").decode("unicode_escape")
        return json.loads(s)

    def __flatten_to_dict(self, obj: Any, parent_key: str = "", out: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recursively flattens `obj` into `out` mapping:
          - dict keys → nested keys with `.`
          - list items → keys with `[idx]`
        Additionally, at any leaf string value, attempts Base64 decode and
        further JSON-flattening.
        """
        if out is None:
            out = {}

        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                self.__flatten_to_dict(v, new_key, out)

        elif isinstance(obj, list):
            for idx, v in enumerate(obj):
                new_key = f"{parent_key}[{idx}]"
                self.__flatten_to_dict(v, new_key, out)

        elif isinstance(obj, str):
            # Try Base64 decode
            try:
                decoded_bytes = self.__try_decode_base64(obj)
                # Try UTF-8 decode
                decoded_str = decoded_bytes.decode("utf-8")
            except Exception:
                # Not Base64 or not UTF-8 → keep original string
                out[parent_key] = obj
                return out

            # If we got here, decoded_str is a valid UTF-8 string
            # Now see if it’s JSON
            try:
                nested = json.loads(decoded_str)
            except json.JSONDecodeError:
                # Not JSON → store the decoded string
                out[parent_key] = decoded_str
            else:
                # It is JSON → flatten it recursively under the same key prefix
                self.__flatten_to_dict(nested, parent_key, out)

        else:
            # Scalar (int, float, bool, None)
            out[parent_key] = obj

        return out

    def __parse_kv_pairs(self, s: str) -> Dict[str, Any]:
        """
        Given s (raw text, Base64-JSON, or quoted JSON),
        return a flat dict of all key→value, with Base64 leaves decoded
        or re-flattened if they contained JSON.
        """
        # Try Base64 decode top-level
        try:
            decoded = base64.b64decode(s, validate=True).decode("utf-8")
            text = decoded
        except Exception:
            text = s

        # Load JSON (stripping outer quotes if needed)
        try:
            data = self.__load_maybe_quoted_json(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Input is not valid JSON or Base64-JSON: {e}")

        # Flatten everything, with per-leaf Base64 handling
        return self.__flatten_to_dict(data)


if __name__ == "__main__":
    logger = setup_logger(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), "netTraceCollector.log")
    parser = TraceParser(output_folder="path/to/networkTracesJson",
                         spacy_model_path="path/to/spacy_model_object",
                         kvps_action=ClusteringKeyValuePair.discard_kvps)
    parser.run()
