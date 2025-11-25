import base64
import json
import logging

from mitmproxy import http
from mitmproxy.coretypes.multidict import MultiDictView, MultiDict
from mitmproxy.http import Request, Response
from mitmproxy.tcp import TCPFlow
from mitmproxy.tls import ClientHelloData
from mitmproxy import ctx
from mitmproxy.utils import strutils

logger = logging.getLogger(__name__)
logging.getLogger("hpack").setLevel(logging.CRITICAL)


class CapturedTraffic:
    def __init__(self, request: Request, source_port: int, response: Response = None):
        self.request = request
        self.response = response
        self.source_port = source_port

    def __repr__(self):
        return f"CapturedTraffic(request={self.request}, response={self.response})"

    def __eq__(self, other):
        if isinstance(other, CapturedTraffic):
            return self.request == other.request and self.response == other.response
        return False

    def __hash__(self):
        return hash((self.request, self.response))

    @staticmethod
    def serialize_cookies(cookies_view: MultiDict[str, str]):
        """
        Serialize a MultiDictView containing cookie data into a JSON-serializable dictionary.

        :param cookies_view: MultiDictView[str, tuple[str, MultiDict[str, str | None]]]
        :return: Serialized dictionary
        """

        # TODO
        # FIX Serialization of multidictview


        serialized = {}
        fields = cookies_view.fields
        #logger.debug(f"Cookies: {cookies_view.__str__()}")
        for key, value in fields:
            #logger.debug(f"Key: {key} <->  Value: {value}")
            if isinstance(value, str):
                serialized[key] = value

        #logger.debug(f"Serialized: {serialized}")
        return serialized




    @staticmethod
    def serialize_multidictview(view: MultiDictView[str, str]):
        try:
            # Get the fields using the getter method
            fields_data = view.fields

            # Convert the fields data into a dictionary-compatible structure
            # Fields data is a list of tuples, so we directly return that
            return dict(fields_data)
        except Exception as e:
            # In case of an error, log it (optional) and return an empty dict
            logger.debug(f"Error serializing MultiDictView: {e}")
            return {}  # Return an empty dictionary

    @staticmethod
    def serialize_multidictview_bytes(view: MultiDictView[bytes, bytes]):
        try:
            fields_data = view.fields
            serialized_dict = {}

            for key, value in fields_data:
                # Decode the key if it's bytes
                if isinstance(key, bytes):
                    key = key.decode("utf-8")

                # Decode the value if it's bytes (Base64 decode if necessary)
                if isinstance(value, bytes):
                    try:
                        value = base64.b64decode(value).decode("utf-8")  # Attempt to decode as base64
                    except Exception as e:
                        value = value.decode("utf-8")  # If it fails, decode as a normal string

                serialized_dict[key] = value

            return serialized_dict
        except Exception as e:
            logger.debug(f"Error serializing MultiDictView: {e}")
            return {}

    def to_dict(self):
        trace = {}
        try:
            # Problematic objects:
            try:
                request_cookies = self.serialize_multidictview(self.request.cookies)
            except Exception as e:
                logger.debug(f"Exception while serializing request cookies: {e}")
                request_cookies = {}

            try:
                # TODO
                # Implement a better serialization for response cookies
                response_cookies = {}
            except Exception as e:
                logger.debug(f"Exception while serializing response cookies: {e}")
                response_cookies = {}

            try:
                urlencoded_form = self.serialize_multidictview(self.request.urlencoded_form)
            except Exception as e:
                logger.debug(f"Exception while serializing request urlencoded form: {e}")
                urlencoded_form = {}

            try:
                multipart_form = self.serialize_multidictview_bytes(self.request.multipart_form)
            except Exception as e:
                logger.debug(f"Exception while serializing request multipart_form: {e}")
                multipart_form = {}


            trace = {
                "request": {
                    "method": self.request.method or "",
                    "url": self.request.url or "",
                    "real_url": self.request.pretty_url or "",
                    "text": self.request.text or "",
                    "port": self.request.port or "",
                    "source_port": self.source_port or "",
                    "cookies": request_cookies,
                    "path": self.request.path or "",
                    "authority": self.request.authority or "",
                    "host": self.request.host or "",
                    "urlencoded_form": urlencoded_form,
                    "first_line_format": self.request.first_line_format or "",
                    "host_header": self.request.host_header or "",
                    "http_version": self.request.http_version or "",
                    "query": dict(self.request.query) if self.request.query else {},
                    "is_http2": self.request.is_http2 or False,
                    "is_http3": self.request.is_http3 or False,
                    "is_http10": self.request.is_http10 or False,
                    "is_http11": self.request.is_http11 or False,
                    "multipart_form": multipart_form,
                    "path_components": list(self.request.path_components) if self.request.path_components else [],
                    "timestamp_end": self.request.timestamp_end or "",
                    "timestamp_start": self.request.timestamp_start or "",
                    "scheme": self.request.scheme or "",
                    "trailers": dict(self.request.trailers) if self.request.trailers else {},
                    "headers": dict(self.request.headers) if self.request.headers else {}
                },
                "response": {
                    "status_code": self.response.status_code if self.response and self.response.status_code else "",
                    "headers": dict(self.response.headers) if self.response and self.response.headers else {},
                    "timestamp_start": self.response.timestamp_start if self.response and self.response.timestamp_start else "",
                    "timestamp_end": self.response.timestamp_end if self.response and self.response.timestamp_end else "",
                    "trailers": dict(self.response.trailers) if self.response and self.response.trailers else {},
                    "is_http11": self.response.is_http11 if self.response and self.response.is_http11 else False,
                    "is_http10": self.response.is_http10 if self.response and self.response.is_http10 else False,
                    "is_http3": self.response.is_http3 if self.response and self.response.is_http3 else False,
                    "is_http2": self.response.is_http2 if self.response and self.response.is_http2 else False,
                    "http_version": self.response.http_version if self.response and self.response.http_version else "",
                    "cookies": response_cookies,
                    "text": self.response.text if self.response and self.response.text else "",
                    "reason": self.response.reason if self.response and self.response.reason else ""
            }

            }

            #logger.debug(f"Returning dict of trace: {self.request.pretty_url}")
            json.dumps(trace)  # Try to convert the dictionary to JSON
        except Exception as e:
            logger.error(f"Invalid JSON: {e}")
        finally:
            return trace



    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)


class TrafficInterceptor:
    def __init__(self):
        self.temporary_store = []  # Stores ongoing requests
        self.results = []  # Stores completed requests with responses
        self.conn_ports = {}
        self.__parsed_conns = set()

    def request(self, flow: http.HTTPFlow):
        # As the request is received, store it in the temporary_store (to avoid situations
        # where a request is ignored because it got no response
        client_ip, client_port = flow.client_conn.address

        logger.debug(f"{flow.request.pretty_url}")
        conn_id = flow.client_conn.id
        port = self.conn_ports.get(conn_id, -1)
        entry = CapturedTraffic(request=flow.request, source_port=port)
        self.temporary_store.append(entry)

    def response(self, flow: http.HTTPFlow):
        # Everytime a response is retrieved, we check to see if there is
        # a corresponding request in the temporary store, in which case, it's
        # added to the main list, and removed from the temporary_store. This is to
        # avoid ignoring requests which did not get a response.
        found_request = False
        for entry in self.temporary_store:
            if entry.request == flow.request:
                entry.response = flow.response
                self.results.append(entry)
                self.temporary_store.remove(entry)
                found_request = True
                break

        # If there was no request in the temp list, just add both to the main list
        if not found_request:
            conn_id = flow.client_conn.id
            port = self.conn_ports.get(conn_id, -1)
            self.results.append(CapturedTraffic(request=flow.request, response=flow.response, source_port=port))

    def get_results(self):
        final_results = self.results.copy()
        for entry in self.temporary_store:
            final_results.append(CapturedTraffic(request=entry.request, response=None, source_port=entry.source_port))

        return final_results

# def test():
#     logger.debug("Testing logger")
#     asyncio.run(run_mitm())
#
#
# if __name__ == "__main__":
#     asyncio.run(run_mitm())
