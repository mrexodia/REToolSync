# Reference: https://www.georgeho.org/tornado-websockets/
import json
import traceback
import urllib.parse
import uuid
from typing import Any, Awaitable, Optional, Set, Union, Dict, List

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.web
import tornado.httputil
import tornado.escape
import tornado.httpclient

def encode_url_params(endpoint: str, path: str, params: Dict[str, str]):
    url = endpoint
    if not url.endswith("/"):
        url += "/"
    url += path
    for i, (key, value) in enumerate(params.items()):
        if i == 0:
            url += "?"
        else:
            url += "&"
        url += f"{urllib.parse.quote(key)}={urllib.parse.quote(value)}"
    return url

# TODO: properly define client features

class AbstractClient:
    client_id: int

    async def client_send(self, request: str, params: Dict[str, str], data: Any):
        raise NotImplementedError()

    @property
    def client_info(self) -> dict:
        raise NotImplementedError()

    def client_removed(self):
        pass

    def client_features(self):
        return []

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(id: {self.client_id})"

class Server:
    # These are (global) class variables
    __unique_id = 1
    __clients: Dict[int, AbstractClient] = dict()

    @staticmethod
    def get_clients() -> List[AbstractClient]:
        return list(Server.__clients.values())

    @staticmethod
    def add_client(client: AbstractClient) -> None:
        client.client_id = Server.__unique_id
        Server.__unique_id += 1
        Server.__clients[client.client_id] = client
        print(f"Added {client}")

    @staticmethod
    def remove_client(client: AbstractClient) -> None:
        if client.client_id not in Server.__clients:
            raise IndexError(f"No such client: {client}")
        client.client_removed()
        print(f"Removed {client}")
        del Server.__clients[client.client_id]

    @staticmethod
    async def send_request(request: str, params: Dict[str, str], data: Any = None):
        # TODO: await?
        for client in Server.__clients.values():
            await client.client_send(request, params, data)

class WebSocketClient(tornado.websocket.WebSocketHandler, AbstractClient):
    def __init__(self, application: tornado.web.Application, request: tornado.httputil.HTTPServerRequest, **kwargs: Any) -> None:
        super().__init__(application, request, **kwargs)
        self.info = {}

    @property
    def client_info(self) -> dict:
        return self.info

    async def client_send(self, request: str, params: Dict[str, str], data: Any):
        # TODO: well-defined packet structure
        await self.write_message({
            **params,
            "request": request,
            "data": data,
        })

    def open(self):
        Server.add_client(self)
        user_agent = dict(self.request.headers.get_all()).get("User-Agent", "Unknown")

        # Add some information
        self.info.update({
            "ip": self.request.remote_ip,
            "agent": user_agent
        })
        print(f"open ({self.info})")

    # on_close is only called when the client hangs up(?) https://stackoverflow.com/a/21122752/1806760
    def on_connection_close(self) -> None:
        print(f"connection_close {self.client_id}")
        Server.remove_client(self)
        return super().on_connection_close()

    def on_message(self, message) -> Optional[Awaitable[None]]:
        try:
            print(f"message {self.client_id}: {message}")
            self.info.update(json.loads(message))
        except:
            traceback.print_exc()
        super().on_finish()

    def on_ping(self, data: bytes) -> None:
        #print(f"ping {self.id}")
        return

    # https://www.tornadoweb.org/en/stable/websocket.html#configuration
    def check_origin(self, origin: str) -> bool:
        return True

# Relevant reading:
# - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
# - https://developer.chrome.com/blog/private-network-access-preflight/
# - https://wicg.github.io/private-network-access
# - https://stackoverflow.com/a/66555660
class CorsHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")

    def options(self, *args):
        self.set_header("Access-Control-Allow-Methods", "*")
        self.set_header("Access-Control-Request-Credentials", "true")
        self.set_header("Access-Control-Allow-Private-Network", "true")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_status(204)  # No Content

class HTTPClient(AbstractClient):
    def __str__(self) -> str:
        return f"HTTPClient(id: {self.client_id}, endpoint: {self.endpoint})"

    def __init__(self, ping_interval: int, endpoint: str) -> None:
        self.endpoint = endpoint
        if self.endpoint.endswith("/"):
            self.endpoint = self.endpoint[:-1]
        self.periodic = tornado.ioloop.PeriodicCallback(self.ping_callback, ping_interval * 1000.0)
        self.info = {
            "endpoint": self.endpoint,
        }
        self.http = tornado.httpclient.AsyncHTTPClient()
        self.ping_failures = 0
        self.max_failures = 3

    async def ping(self):
        try:
            request = tornado.httpclient.HTTPRequest(self.endpoint + "/ping", "GET")
            response = await self.http.fetch(request)
            #print(f"Client {self.client_id} /ping -> {response.body}")
            return 200 >= response.code <= 299
        except Exception as e:
            print(f"Client {self.client_id} /ping error -> {e}")
            return False

    async def ping_callback(self):
        ping_ok = await self.ping()
        if not ping_ok:
            self.ping_failures += 1
            if self.ping_failures >= self.max_failures:
                Server.remove_client(self)
        else:
            self.ping_failures = 0

    async def client_send(self, request: str, params: Dict[str, str], data: Any):
        # TODO: check if this client supports the request
        url = encode_url_params(self.endpoint, request, params)
        if data is None:
            data = b""
        try:
            # TODO: support custom headers
            request = tornado.httpclient.HTTPRequest(url, "POST", body=data)
            response = await self.http.fetch(request, False)
            print(f"Client {self.client_id} {url} -> HTTP {response.code}: {response.body}")
        except Exception as e:
            print(f"Client {self.client_id} {url} error -> {e}")

    @property
    def client_info(self) -> dict:
        return self.info

    def client_removed(self):
        if self.periodic.is_running():
            self.periodic.stop()

class ClientsHandler(CorsHandler):
    __tokens: Dict[str, HTTPClient] = dict()

    def set_default_headers(self):
        self.set_header("Content-Type", "application/json")

    def get(self):
        token = self.get_query_argument("token", None)
        if token is None:
            clients = [client.client_info for client in Server.get_clients()]
            self.write(json.dumps(clients))
        else:
            client = ClientsHandler.__tokens.get(token, None)
            if client is None:
                return self.set_status(404)
            self.write(json.dumps(client.client_info))

    async def post(self):
        data = tornado.escape.json_decode(self.request.body)
        if "endpoint" not in data:
            self.write("Missing 'endpoint' key in body")
            return self.set_status(400)

        ping_interval = 1

        endpoint = data["endpoint"]
        client = HTTPClient(ping_interval, endpoint)
        Server.add_client(client)
        ping_ok = await client.ping()
        if not ping_ok:
            Server.remove_client(client)
            self.write(f"No pong from {client.endpoint}/ping")
            return self.set_status(400)
        else:
            client.periodic.start()
            token = str(uuid.uuid4())
            ClientsHandler.__tokens[token] = client
            self.write(json.dumps({
                "token": token,
            }))

    def delete(self):
        token = self.get_query_argument("token")
        client = ClientsHandler.__tokens.get(token, None)
        if client is None:
            self.write(f"Invalid token: {token}")
            return self.set_status(400)
        del ClientsHandler.__tokens[token]
        Server.remove_client(client)

class PingHandler(CorsHandler):
    def get(self):
        self.write(b"pong")

class GotoHandler(CorsHandler):
    async def post(self):
        address = self.get_query_argument("address")
        print(f"goto:{address}")
        await Server.send_request("goto", {
            "address": address,
        })
        self.write(f"Notified {len(Server.get_clients())} clients")

def main():
    # TODO: configuration
    ip, port = "0.0.0.0", 6969

    app = tornado.web.Application(
        [
            (r"/REToolSync", WebSocketClient),
            (r"/api/ping", PingHandler),
            (r"/api/clients", ClientsHandler),
            (r"/api/goto", GotoHandler)
        ],
        websocket_ping_interval=10,
        websocket_ping_timeout=30,
    )
    app.listen(port=port, address=ip)
    print(f"Listening on {ip}:{port}")

    # Create an event loop (what Tornado calls an IOLoop).
    io_loop = tornado.ioloop.IOLoop.current()

    # Start the event loop.
    io_loop.start()


if __name__ == "__main__":
    main()