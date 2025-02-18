"""
This file implemlents a no-JavaScript real-time, web-based chat interface, by using HTTP 1.1 "chunked transfer
encoding", along with HTML iframes, forms, and (aspirationally) some clever CSS rules.

The home/intro page allows users to specify a nickname via form submission. The resulting page has two frames: one
for displaying real-time chat messages (by leaving the connection open using chunked transfer encoding), and one with
a form for sending messages. Messages are correlated back to clients using a random, unique id.
"""

# TODO: Validate id, nick, etc. formats -- basically anything from the client!
# TODO: Probably better to have two iframes, that way something loads quickly, even in Firefox!

from enum import StrEnum
from html import escape
from http import HTTPStatus
from random import choices
from string import ascii_lowercase
from urllib.parse import parse_qs, quote, urlparse
from pirc import TcpServer
import re
import socket

#### Generic select-based HTTP server
crlf = "\r\n".encode("utf-8")
status_to_text = { v.value: v.phrase for v in HTTPStatus.__members__.values() }

# TODO: Need HEAD/etc.?
request_pattern = r"^(?P<method>GET|POST) (?P<path>[^ ]+?) (?P<version>HTTP/.+)$"
header_pattern = r"^(?P<key>[^:]+): (?P<value>.+)$"

class ContentType(StrEnum):
    HTML = "text/html"

class HttpClientBase:
    def __init__(self, socket: socket.socket) -> None:
        self.socket = socket

class HttpInput:
    def __init__(self, input: bytes):
        self.input = input

    def read_line(self) -> str:
        index = self.input.find(crlf, 0)
        if index == -1:
            raise ValueError("No end of line!")
        result = str(self.input[0:index], "utf-8")
        self.input = self.input[index+2:]
        return result
    
    def read(self, length: int) -> bytes:
        result = self.input[0:length]
        self.input = self.input[length:]
        return result
    
    def remaining(self) -> int:
        return len(self.input)

class HttpRequest:
    def __init__(self, method: str, path: str, headers: dict[str, str], body: bytes|None):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

class HttpServer(TcpServer):
    def __init__(
            self,
            host="localhost",
            port=1234,
            max_message_size=65536,
            max_pending_clients=5,
            max_select_timeout=None
            ):
        super().__init__(host, port, max_message_size, max_pending_clients, max_select_timeout)

    def send_text_raw(self, client: HttpClientBase, message: str) -> None:
        encoded = message.encode("utf-8")
        client.socket.sendall(encoded)
    
    def send_response_start(self, client: HttpClientBase, status: int, headers: list[tuple[str, str]], protocol_version="1.0") -> None:
        text = f"HTTP/{protocol_version} {int(status)} {status_to_text[status]}\r\n"
        for key, value in headers:
            text += f"{key}: {value}\r\n"
        text += "\r\n"
        self.send_text_raw(client, text)

    def send_response_body(self, client: HttpClientBase, body: bytes) -> None:
        client.socket.sendall(body)

    def send_response(self, client: HttpClientBase, status: int, headers: list[tuple[str, str]], body: bytes|None=None, protocol_version="1.0") -> None:
        if body:
            headers.append(("Content-Length", str(len(body))))
        self.send_response_start(client, status, headers, protocol_version)
        if body:
            self.send_response_body(client, body)
        self.remove_client(client.socket)

    def send_html_chunk(self, client: HttpClientBase, html: str) -> None:
        encoded = html.encode("utf-8")
        client.socket.sendall(f"{len(encoded):x}".encode("utf-8"))
        client.socket.sendall(crlf)
        client.socket.sendall(encoded)
        client.socket.sendall(crlf)

    def send_html_chunked_start(self, client: HttpClientBase, start: str) -> None:
        """IMPORTANT: In Firefox, incremental rendering won't start until at least one delayed chunk is sent!"""
        self.send_response_start(client, HTTPStatus.OK, [
            ("Content-Type", ContentType.HTML),
            ("Transfer-Encoding", "chunked"),
        ], "1.1") # HTTP 1.1 is required for chunked transfer encoding

        # For Firefox to start rendering we need at least 1 KB and at least one delayed chunk
        min_length = 1024
        if len(start) <= min_length:
            start = start + ("\n" * (min_length - len(start)))
        self.send_html_chunk(client, start)

    def handle(self, client_data: HttpClientBase, message: bytes) -> None:
        # Parse method, version
        input = HttpInput(message)
        start = re.match(request_pattern, input.read_line())
        if not start: raise SyntaxError("Invalid request start!")
        method, path = start["method"], start["path"]

        # Parse headers
        headers: dict[str, str] = dict()
        while (line := input.read_line()) != "":
            header = re.match(header_pattern, line)
            if not header: raise SyntaxError("Invalid request header!")
            headers[header["key"]] = header["value"]

        # Parse body
        body = None
        if "Content-Length" in headers:
            content_length = int(headers["Content-Length"])
            if content_length > input.remaining(): raise ValueError("Not enough content!")
            body = input.read(content_length)

        self.handle_request(client_data, HttpRequest(method, path, headers, body))

    def handle_request(self, client: HttpClientBase, request: HttpRequest) -> None:
        raise NotImplementedError()

#### Chat server implementation
def generate_id() -> str:
    # Use an id to correlate form submissions to originating chat client
    return "".join(choices(ascii_lowercase, k=10))

class Client(HttpClientBase):
    def __init__(self, client: socket.socket) -> None:
        super().__init__(client)
        self.sent_delayed_chunk = False # Needed to support chunked transfer encoding on Firefox...

# "Choose your nickname" page (root)
def html_home() -> str:
    return f"""
<form action="chat" method="get">
<label>Nickname: </label>
<input type="text" name="nick">
<input type="hidden" name="id" value="{escape(generate_id())}">
<input type="submit" value="Connect">
</form>
"""

# "Main chat window (with iframe for input)" page (/chat)
def html_chat_header(id: str, nick: str) -> str:
    return f"""
Hi, {escape(nick)}<br>
<iframe id="input" src="input?id={quote(id)}"></iframe>

<div class="messages">
"""

# "Show input, and send previous input (if applicable)" page (/input AND /post)
def html_input(client_id: str) -> str:
    return f"""
<form action="post" method="post">
<input type="text" name="message" autofocus>
<input type="hidden" name="id" value="{escape(client_id)}">
<input type="submit" value="Send">
</form>
"""

class ChatServer(HttpServer):
    def __init__(
            self,
            host="localhost",
            port=1234,
            max_pending_clients=5,
            max_message_size=65536
            ):
        super().__init__(host, port, max_message_size, max_pending_clients, 2)
        self.id_to_nick: dict[str, str] = dict()

    def create_client_data(self, client: socket.socket):
        return Client(client)
    
    def send_error_response(self, client: HttpClientBase, status: int) -> None:
        self.send_response(client, status, [])

    def send_html_response(self, client: HttpClientBase, html: str) -> None:
        self.send_response(client, HTTPStatus.OK, [("Content-Type", ContentType.HTML)], html.encode("utf-8"))

    def on_idle(self):
        for _socket, client in self.enumerate_clients():
            assert isinstance(client, Client)
            if not client.sent_delayed_chunk:
                self.send_html_chunk(client, "\n\n")
                client.sent_delayed_chunk = True

    def handle_request(self, client: HttpClientBase, request: HttpRequest) -> None:
        match request.method:
            case "GET":
                parsed = urlparse(request.path, allow_fragments=False)
                match parsed.path:
                    case "/":
                        self.send_html_response(client, html_home())
                    case "/chat":
                        assert isinstance(client, Client)
                        parameters = parse_qs(parsed.query)
                        nick = parameters["nick"][0]
                        id = parameters["id"][0]
                        self.id_to_nick[id] = nick
                        self.send_html_chunked_start(client, html_chat_header(id, nick))
                    case "/input":
                        id = parse_qs(parsed.query)["id"][0]
                        self.send_html_response(client, html_input(id))
                    case _:
                        self.send_error_response(client, HTTPStatus.NOT_FOUND)
            case "POST":
                parsed = urlparse(request.path, allow_fragments=False)
                match parsed.path:
                    case "/post":
                        if request.body:
                            assert isinstance(client, Client)
                            parameters = parse_qs(str(request.body, "utf-8"))
                            id = parameters["id"][0]
                            self.send_html_response(client, html_input(id))
                            # TODO: Can this block for a long time? That would break this architecture!
                            message = parameters["message"][0]
                            html = f"{escape(self.id_to_nick.get(id, "???"))}: {escape(message)}<br>"
                            for _, other in self.enumerate_clients():
                                assert isinstance(other, Client)
                                self.send_html_chunk(other, html)
                    case _:
                        self.send_error_response(client, HTTPStatus.BAD_REQUEST)
            case _:
                self.send_error_response(client, HTTPStatus.BAD_REQUEST)

if __name__ == "__main__":
    server = ChatServer("localhost", 1234)
    server.run()
