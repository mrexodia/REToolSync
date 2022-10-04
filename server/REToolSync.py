# Reference: https://www.georgeho.org/tornado-websockets/
import json
import traceback
from typing import Any, Awaitable, Optional, Set, Union
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.web
import tornado.httputil

class WebSocketServer(tornado.websocket.WebSocketHandler):
    def __init__(self, application: tornado.web.Application, request: tornado.httputil.HTTPServerRequest, **kwargs: Any) -> None:
        super().__init__(application, request, **kwargs)
        self.id = 0
        self.info = {}

    # Note that `clients` is a class variable and `send_message` is a
    # classmethod.
    clients = set()
    unique_id = 1

    def open(self):
        WebSocketServer.clients.add(self)
        self.id = WebSocketServer.unique_id
        WebSocketServer.unique_id += 1
        user_agent = dict(self.request.headers.get_all()).get('User-Agent', 'Unknown')

        # Add some information
        self.info.update({
            'id': self.id,
            'ip': self.request.remote_ip,
            'agent': user_agent
        })
        print(f"open ({self.info})")

    # on_close is only called when the client hangs up(?) https://stackoverflow.com/a/21122752/1806760
    def on_connection_close(self) -> None:
        print(f"connection_close {self.id}")
        WebSocketServer.clients.remove(self)
        return super().on_connection_close()

    def on_message(self, message) -> Optional[Awaitable[None]]:
        try:
            print(f"message {self.id}: {message}")
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

    @classmethod
    def send_message(cls, message: str):
        print(f"Sending message {message} to {len(cls.clients)} client(s).")
        client: WebSocketServer
        for client in cls.clients:
            client.write_message(message)


class ClientsHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Content-Type", 'application/json')

    def get(self):
        clients = []
        client: WebSocketServer
        for client in WebSocketServer.clients:
            clients.append(client.info)
        self.write(json.dumps(clients))

class GotoHandler(tornado.web.RequestHandler):
    def post(self):
        address = self.get_query_argument("address")
        WebSocketServer.send_message(json.dumps({
            "request": "goto",
            "address": address,
        }))
        self.write(f"Notified {len(WebSocketServer.clients)} clients")

def main():
    # TODO: configuration
    ip, port = "127.0.0.1", 6969

    app = tornado.web.Application(
        [
            (r"/REToolSync", WebSocketServer),
            (r"/api/clients", ClientsHandler),
            (r"/api/goto", GotoHandler),
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