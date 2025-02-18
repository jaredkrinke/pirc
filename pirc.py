import logging
import random
import re
import selectors
import socket
import string
import sys
import textwrap
from _collections_abc import Iterable
from enum import Enum
from os import environ

# Note: You can set PIRC_LOG_LEVEL=10 to enable DEBUG (10) level logging
log = logging.getLogger("pirc")

# Generic select-based TCP server
class TcpServer:
    def __init__(self, host="localhost", port=1234, max_message_size=1000, max_pending_clients=5, max_select_timeout: float|None = None) -> None:
        self.host = host
        self.port = port
        self.max_pending_clients = max_pending_clients
        self.max_message_size = max_message_size
        self.max_select_timeout = max_select_timeout

    def run(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setblocking(False)
        self.listener.bind((self.host, self.port))
        self.listener.listen(self.max_pending_clients)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.listener, selectors.EVENT_READ)
        log.info(f"Listening on: {self.host}:{self.port}")
        while True:
            events = self.selector.select(self.max_select_timeout)
            for key, _mask in events:
                assert isinstance(key.fileobj, socket.socket)
                if key.fileobj == self.listener: self.accept()
                else: self.read(key.fileobj, key.data)
            if not events and hasattr(self, "on_idle"): getattr(self, "on_idle")()

    def accept(self) -> None:
        client, _address = self.listener.accept()
        client_data = self.create_client_data(client)
        client.setblocking(False)
        self.selector.register(client, selectors.EVENT_READ, client_data)
    
    def remove_client(self, client: socket.socket) -> None:
        self.selector.unregister(client)
        client.close()
            
    def read(self, client: socket.socket, client_data) -> None:
        try:
            message = client.recv(self.max_message_size)
            if not message: raise ConnectionError()
            self.handle(client_data, message)
        except Exception as e:
            # Treat all errors as disconnections
            log.warning("Exception while handling read", exc_info=e)
            self.remove_client(client)

    def send(self, client: socket.socket, message: bytes):
        client.sendall(message)

    def enumerate_clients(self, excluded: socket.socket|None = None) -> list[tuple[socket.socket, type]]:
        result = []
        for _f, k in self.selector.get_map().items():
            if not (k.fileobj == self.listener or k.fileobj == excluded):
                assert isinstance(k.fileobj, socket.socket)
                result.append((k.fileobj, k.data))
        return result

    def create_client_data(self, client: socket.socket):
        raise NotImplementedError()

    def handle(self, client_data, message: bytes) -> None:
        raise NotImplementedError()

# IRC command parser
command_pattern = r"^(?P<source>:[a-zA-Z0-9@#*_.+!\[\]{}\\|\-]+ )?(?P<command>([A-Z]+)|motd)(?P<subcommands>( [a-zA-Z0-9@#*_.+!\[\]{}\\|\-]+)*?)( :(?P<content>.*))?$"

class Command:
    def __init__(self, text: str) -> None:
        # Parse message
        match = re.match(command_pattern, text)
        if not match: raise SyntaxError("Invalid message received!")
        source = match["source"]
        subcommands = match["subcommands"]
        self.source = source[1:-1] if source else None
        self.command = match["command"]
        self.subcommands = subcommands.strip().split(" ") if subcommands else None
        self.content = match["content"]
    
    def __repr__(self):
        return f"Command: {self.command}, Subcommands: {repr(self.subcommands)}, Content: {self.content}"

# IRC client representation
def random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=7))

def compute_id(nick: str, user: str, host: str) -> str:
    return f"{nick}!{user}@{host}"

class ClientRegistration:
    def __init__(self, client: socket.socket) -> None:
        self.client = client
        self.nick = f"n{random_id()}"
        self.nick_set = False
        self.user = f"u{random_id()}"
        self.host = f"h{random_id()}"
        self.channels = []

    def id(self) -> str:
        return compute_id(self.nick, self.user, self.host)

# IRC numeric replies
class Reply(Enum):
    Welcome = 1
    YourHost = 2
    Created = 3
    MyInfo = 4
    ISupport = 5
    ListStart = 321
    List = 322
    ListEnd = 323
    Topic = 332
    NameReply = 353
    EndOfNames = 366
    Motd = 372
    MotdStart = 375
    EndOfMotd = 376
    NoMotd = 422
    NicknameInUse = 433

# Server
class IrcServer(TcpServer):
    def __init__(
            self,
            host="localhost",
            port=1234,
            max_pending_clients=5,
            network_name="pircnet",
            server_name="pirc",
            motd: Iterable[str]=[],
            ):
        super().__init__(host, port, 512, max_pending_clients)
        self.network_name = network_name
        self.server_name = server_name
        self.version = 0.1
        self.channels: dict[str, list[ClientRegistration]] = dict()
        self.users: dict[str, ClientRegistration] = dict()
        self.motd = []
        for line in motd:
            for l in (textwrap.wrap(line) if line else [""]):
                self.motd.append(l)

    def encode(self, message: str) -> bytes:
        return f"{message}\r\n".encode("utf-8")

    def send_text_each(self, clients: Iterable[ClientRegistration], message: str, excluded: ClientRegistration|None = None) -> None:
        log.debug(f"-->  {message}")
        bytes = self.encode(message)
        for client_data in clients:
            if not client_data == excluded:
                try:
                    self.send(client_data.client, bytes)
                except Exception as e:
                    log.warning("Exception while sending; disconnecting client", exc_info=e)
                    self.remove_client(client_data.client)

    def create_client_data(self, client: socket.socket) -> ClientRegistration:
        client_data = ClientRegistration(client)
        self.users[client_data.nick] = client_data
        return client_data
    
    def handle(self, client_data: ClientRegistration, message: bytes) -> None:
        text = message.decode("utf-8")
        lines = text.strip().split("\r\n")
        for line in lines:
            log.debug(f"<-- {line}")
            self.handle_command(client_data, Command(line))
    
    def reply(self, client_data: ClientRegistration, text: str) -> None:
        self.send_text_each([client_data], text)

    def reply_numeric(self, client_data: ClientRegistration, reply: Reply, text: str) -> None:
        self.reply(client_data, f"{str(reply.value).zfill(3)} {client_data.nick} {text}")

    def reply_numerics(self, client_data: ClientRegistration, replies: list[tuple[Reply, str]]) -> None:
        for reply, text in replies:
            self.reply_numeric(client_data, reply, text)

    def channel_get(self, channel: str) -> list[ClientRegistration]:
        if not channel in self.channels:
            self.channels[channel] = []
        return self.channels[channel]
    
    # Note: Needed a safe way to retrieve members of a channel, even if a channel was just deleted
    def channel_get_members(self, channel: str) -> list[ClientRegistration]:
        return self.channels[channel] if channel in self.channels else []

    def leave_channel(self, client_data: ClientRegistration, channel: str):
        if channel in self.channels:
            list = self.channels[channel]
            if client_data in list:
                list.remove(client_data)
                if len(list) <= 0:
                    del self.channels[channel]
        if channel in client_data.channels:
            client_data.channels.remove(channel)

    def remove_client(self, client: socket.socket, reason = "") -> None:
        # Need to also remove from user/channel dictionaries and send QUIT messages
        key = self.selector.get_map().get(client)
        client_data = key.data if key else None
        super().remove_client(client)
        if client_data:
            # Remove from user list
            assert isinstance(client_data, ClientRegistration)
            if client_data.nick in self.users:
                del self.users[client_data.nick]
            # Remove from channels
            neighbors = set()
            for channel in client_data.channels:
                if channel in self.channels:
                    self.leave_channel(client_data, channel)
                    neighbors = neighbors.union(self.channel_get_members(channel))
            # Send QUIT updates to interested (i.e. in shared channel) clients
            self.send_text_each(neighbors, f":{client_data.id()} QUIT :Quit: {reason}")
            log.info(f"User disconnected: {client_data.id()}")

    def send_motd(self, client_data: ClientRegistration) -> None:
        if self.motd:
            for i, line in enumerate(self.motd):
                self.reply_numeric(client_data, Reply.MotdStart if i == 0 else Reply.Motd, f":- {line}")
            self.reply_numeric(client_data, Reply.EndOfMotd, ":-")
        else:
            self.reply_numeric(client_data, Reply.NoMotd, ":MOTD File is missing")

    def handle_command(self, client_data: ClientRegistration, command: Command) -> None:
        match command.command:
            case "CAP":
                if command.subcommands:
                    match command.subcommands[0]:
                        case "LS":
                            self.reply(client_data, "CAP * ACK")
            case "NICK":
                if command.subcommands and len(command.subcommands) >= 1:
                    nick = command.subcommands[0]
                    if nick in self.users:
                        self.reply_numeric(client_data, Reply.NicknameInUse, ":Nickname already in use")
                    else:
                        old_nick = client_data.nick
                        if old_nick in self.users: del self.users[old_nick]
                        client_data.nick = nick
                        self.users[nick] = client_data
                        if client_data.nick_set:
                            self.send_text_each([client_data], f":{compute_id(old_nick, client_data.user, client_data.host)} NICK {nick}")
                        client_data.nick_set = True
            case "USER":
                if command.subcommands and len(command.subcommands) >= 1:
                    client_data.user = command.subcommands[0]
                    self.reply_numerics(client_data, [
                        (Reply.Welcome,     f":Welcome, {client_data.id()}"),
                        (Reply.YourHost,    f":Your host is {self.server_name}, running version {self.version}"),
                        (Reply.Created,     ":This server was created today"),
                        (Reply.MyInfo,      f"{self.server_name} {self.version}  "),
                        (Reply.ISupport,    f"NETWORK={self.network_name} :are supported by this server"),
                    ])
                    self.send_motd(client_data)
                    log.info(f"New user connected: {client_data.id()}")
            case "MOTD" | "motd": # Very strange that this is sent in lowercase, unlike all other commands...
                self.send_motd(client_data)
            case "PING":
                if command.subcommands:
                    self.reply(client_data, f'PONG {" ".join(command.subcommands)}')
            case "JOIN":
                # TODO: Manage topics?
                if command.subcommands:
                    channels = command.subcommands[0].split(",")
                    for channel in channels:
                        if len(channel) >= 1 and channel[0] == "#":
                            if not channel in client_data.channels:
                                client_data.channels.append(channel)
                                clients = self.channel_get(channel)
                                clients.append(client_data)
                                self.send_text_each(clients, f":{client_data.id()} JOIN {channel}")
                                # TODO: Split nick list, if needed
                                self.reply_numerics(client_data, [
                                    (Reply.Topic, f"{channel} :topic"),
                                    (Reply.EndOfNames, f"{channel} :End of /NAMES list"),
                                    (Reply.NameReply, f"= {channel} :{','.join([c.nick for c in clients])}"),
                                ])
            case "QUIT":
                self.remove_client(client_data.client, command.content if command.content else "")
            case "PART":
                if command.subcommands and len(command.subcommands) >= 1:
                    channels = command.subcommands[0].split(",")
                    for channel in channels:
                        if len(channel) >= 1 and channel[0] == "#" and channel in self.channels and channel in client_data.channels:
                            self.leave_channel(client_data, channel)
                            self.send_text_each([client_data, *self.channel_get_members(channel)], f":{client_data.id()} PART {channel}")
            case "LIST":
                self.reply_numeric(client_data, Reply.ListStart, "Channel :Users  Name")
                for channel, clients in self.channels.items():
                    self.reply_numeric(client_data, Reply.List, f"{channel} {len(clients)} :")
                self.reply_numeric(client_data, Reply.ListEnd, "End of /LIST")
            case "PRIVMSG":
                if command.subcommands and len(command.subcommands) >= 1:
                    targets = command.subcommands[0].split(",")
                    for target in targets:
                        message = f":{client_data.id()} PRIVMSG {target} :{command.content}"
                        if len(target) >= 1 and target[0] == "#":
                            if target in self.channels and client_data in self.channels[target]:
                                self.send_text_each(self.channels[target], message, client_data)
                        else:
                            if target in self.users:
                                self.send_text_each([self.users[target]], message)

def print_usage():
    print(f"\nUSAGE: {sys.argv[0]} <host/IP>[:<port>] [MOTD file]\n")

if __name__ == "__main__":
    logging.basicConfig(level = int(environ.get("PIRC_LOG_LEVEL", logging.INFO)))

    if len(sys.argv) <= 1 or sys.argv[1] == "--help":
        print_usage()
        exit(0)

    motd = ""
    if len(sys.argv) >= 3:
        with open(sys.argv[2]) as f:
            motd = f.read().splitlines()

    bind_info = re.match(r"^(?P<host>[^:]*?)(:(?P<port>[0-9]+))?$", sys.argv[1])
    if (not bind_info):
        print(f"ERROR: couldn't parse bind info: \"{sys.argv[1]}\"")
        print_usage()
        exit(-1)

    server = IrcServer(host=bind_info["host"], port=int(bind_info["port"] or 6667), motd=motd)
    server.run()
