from glob import glob
import os
import json
import asyncio
import queue
import threading
import traceback
import struct
import time
import logging
from typing import Tuple

from binaryninja import *
from binaryninjaui import *

import tornado.ioloop
import tornado.websocket
import tornado.httpclient

def get_static_info():
    # TODO
    return {
        'path': '',
        'module': '',
        'base': hex(0),
        'size': hex(0),
        'md5': '',
        'sha256': '',
        'crc32': hex(0),
        'filesize': hex(0),
    }

global_cursor = None
global_selection = None
global_frame = None

def get_cursor() -> int:
    global global_cursor
    return global_cursor

def get_selection() -> Tuple[bool, int, int]:
    global global_selection
    if global_selection is None:
        return False, 0, 0
    else:
        return True, global_selection[0], global_selection[1]

# Reference: https://www.georgeho.org/tornado-websockets/
# IDAPython cheat sheet: https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c
# https://github.com/inforion/idapython-cheatsheet
class WebSocketClient:
    def __init__(self, io_loop):
        self.connection: tornado.websocket.WebSocketClientConnection = None
        self.periodic_cb = tornado.ioloop.PeriodicCallback(self.timeout, 250)
        self.io_loop = io_loop
        self.num_messages = 0
        self.connection_count = 0
        self.reconnect_count = 0
        self.info = get_static_info()
        self.cursor_info = {}
        self.last_cursor = 0
        self.last_selection = None

    def start(self):
        self.connect_and_read()

    def stop(self):
        if self.connection:
            self.connection.close()
            self.connection = None
        if self.periodic_cb.is_running():
            self.periodic_cb.stop()
        self.io_loop.stop()

    def timeout(self):
        cursor_info = {}
        cursor = get_cursor()
        if cursor is None:
            return
        selection = get_selection()

        cursor_info["address"] = hex(cursor)
        ok, start, end = selection
        if ok:
            cursor_info["selection_start"] = hex(start)
            cursor_info["selection_end"] = hex(end)
        else:
            cursor_info["selection_start"] = None
            cursor_info["selection_end"] = None

        if not cursor_info == self.cursor_info:
            #print(f"[REToolSync] cursor change: ({json.dumps(self.cursor_info)}) -> ({json.dumps(cursor_info)})")
            if self.connection:
                self.connection.write_message(json.dumps({"cursor": [cursor_info]}))

            self.cursor_info = cursor_info

        return

    def connect_and_read(self):
        endpoint = os.environ.get("RETOOLSYNC_ENDPOINT", "127.0.0.1:6969")
        request = tornado.httpclient.HTTPRequest(f"ws://{endpoint}/REToolSync", headers={"User-Agent": f"REToolSync Binary Ninja {os.getpid()}"})
        print(f"[REToolSync] Connecting to {endpoint} ...")
        tornado.websocket.websocket_connect(
            url=request,
            callback=self.maybe_retry_connection,
            on_message_callback=self.on_message,
            ping_interval=10,
            ping_timeout=30,
        )

    def maybe_retry_connection(self, future) -> None:
        try:
            self.connection = future.result()
            print("[REToolSync] Connected to server!")
            self.periodic_cb.start()
            self.connection.write_message(json.dumps(self.info))
            self.connection_count += 1
        except ConnectionError as x:
            self.reconnect_count += 1
            if self.connection_count > 0 and self.reconnect_count < 10:
                print("[REToolSync] Could not reconnect, retrying in 3 seconds...")
                self.io_loop.call_later(3, self.connect_and_read)
            else:
                print("[REToolSync] Failed to connect, use the menu to retry")
                self.stop()
        except Exception as x:
            print(f"[REToolSync] exception: {x}, {type(x)}")
            raise x

    def on_message(self, message):
        if message is None:
            print("[REToolSync] Disconnected, reconnecting in 3 seconds...")
            self.periodic_cb.stop()
            self.io_loop.call_later(3, self.connect_and_read)
            return

        self.num_messages += 1

        msg = json.loads(message)
        if msg.get("request", "") == "goto":
            # Reference: https://github.com/joshwatson/binaryninja-bookmarks/blob/master/__init__.py#L71
            def goto(addr):
                global global_frame
                bv = global_frame.getCurrentBinaryView()
                bv.navigate(bv.file.view, addr)
            address = int(msg["address"], 16)
            print(f"[REToolSync] Goto {hex(address)}")
            mainthread.execute_on_main_thread(lambda: goto(address))
        else:
            print(f"[REToolSync] unsupported message: {message}")

    def write_message(self, message):
        if self.connection:
            self.connection.write_message(message)

def join_gui_thread(thread: threading.Thread, timeout=None):
    iterations = 0
    iteration_timeout = 0.1
    while True:
        if not thread.is_alive():
            return True
        thread.join(iteration_timeout)
        #QtWidgets.QApplication.processEvents()
        if timeout is not None and iteration_timeout * iterations >= timeout:
            return False
        iterations += 1

class Service:
    def __init__(self) -> None:
        self.started = False
        self.client: WebSocketClient = None
        self.wsthread: threading.Thread = None

    def start(self):
        self.stop()
        self.wsthread = threading.Thread(target=self.service_thread)
        self.wsthread.start()
        self.started = True
        print("[REToolSync] Service started")

    def stop(self):
        if not self.started:
            return

        if self.client is not None:
            self.client.stop()

        if not join_gui_thread(self.wsthread, 1.0):
            print("[REToolSync] Waiting for service to stop...")
            if not join_gui_thread(self.wsthread, 5.0):
                print(f"[REToolSync] deadlock while stopping service, please report an issue!\n")
        self.wsthread = None
        self.client = None
        print("[REToolSync] Service stopped")

    def service_thread(self):
        # Create a new event loop for the thread
        # https://github.com/tornadoweb/tornado/issues/2308#issuecomment-372582005
        loop = asyncio.new_event_loop()
        loop.set_debug(False)
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)  # Remove some debug spam
        asyncio.set_event_loop(loop)

        # Before starting the event loop, instantiate a WebSocketClient and add a
        # callback to the event loop to start it. This way the first thing the
        # event loop does is to start the client.
        io_loop = tornado.ioloop.IOLoop.current()
        self.client = WebSocketClient(io_loop)
        io_loop.add_callback(self.client.start)

        # Start the event loop.
        io_loop.start()

        # Signal that the service is finished
        self.started = False

# Reference: https://github.com/Vector35/binaryninja-api/blob/ed820d2ab81470b3e5ac543d75211e87ff3bc738/python/examples/ui_notifications.py
class UINotification(UIContextNotification):
    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)

        self.service = Service()
        self.service.start()

    def __del__(self):
        UIContext.unregisterNotification(self)

        self.service.stop()

    def OnAddressChange(self, context, frame, view, location):
        global global_cursor, global_selection
        global_cursor = location.getOffset()
        if view:
            global_selection = view.getSelectionOffsets()
        else:
            global_selection = None

    def OnViewChange(self, context, frame, t):
        # frame.getCurrentBinaryView() is the global `bv` object or the `view` in other callbacks
        global global_frame
        global_frame = frame

# Register as a global so it doesn't get destructed
notif = UINotification()
