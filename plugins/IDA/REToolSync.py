from __future__ import print_function

import os
import json
import asyncio
import queue
import threading
import traceback
import struct
import time
from typing import Tuple

# pip install tornado
import tornado.ioloop
import tornado.websocket
import tornado.httpclient

import ida_pro
import ida_hexrays
import ida_kernwin
import ida_gdl
import ida_lines
import ida_idaapi
import idc
import idaapi
import idautils
import ida_nalt
import ida_bytes

# Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging

import functools
import idaapi

class IDASyncError(Exception):
    pass

# Important note: Always make sure the return value from your function f is a
# copy of the data you have gotten from IDA, and not the original data.
#
# Example:
# --------
#
# Do this:
#
#   @idaread
#   def ts_Functions():
#       return list(idautils.Functions())
#
# Don't do this:
#
#   @idaread
#   def ts_Functions():
#       return idautils.Functions()
#

logger = logging.getLogger(__name__)

# Enum for safety modes. Higher means safer:
class IDASafety:
    SAFE_NONE = 0
    SAFE_READ = 1
    SAFE_WRITE = 2


call_stack = queue.LifoQueue()


def sync_wrapper(ff, safety_mode: IDASafety):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    #logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode, ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = queue.Queue()

    def runned():
        #logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                'function {} from {}').format(ff.__name__, last_func_name)
            #logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception:
            traceback.print_exc()
            res_container.put(None)
        finally:
            call_stack.get()
            #logger.debug('Finished runned')

    ret_val = idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    return res


def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)
    return wrapper

# This freezes and doesn't gracefully error
# @idaread
def get_image_size():
    # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
    info = idaapi.get_inf_structure()
    # Bad heuristic for image size (bad if the relocations are the last section)
    image_size = info.omax_ea - info.omin_ea
    # Try to extract it from the PE header
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size

@idaread
def get_static_info():
    return {
        'path': idaapi.get_input_file_path(),
        'module': idaapi.get_root_filename(),
        'base': hex(idaapi.get_imagebase()),
        'size': hex(get_image_size()),
        'md5': ida_nalt.retrieve_input_file_md5().hex(),
        'sha256': ida_nalt.retrieve_input_file_sha256().hex(),
        'crc32': hex(ida_nalt.retrieve_input_file_crc32()),
        'filesize': hex(ida_nalt.retrieve_input_file_size()),
    }

@idaread
def get_cursor() -> int:
    return idaapi.get_screen_ea()

@idaread
def get_selection() -> Tuple[bool, int, int]:
    if idaapi.IDA_SDK_VERSION >= 700:
        return idaapi.read_range_selection(None)
    return idaapi.read_selection()

@idaread
def goto_address(address: int) -> None:
    return ida_kernwin.jumpto(address)

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
            print(f"[REToolSync] cursor change: ({json.dumps(self.cursor_info)}) -> ({json.dumps(cursor_info)})")
            if self.connection:
                self.connection.write_message(json.dumps({"cursor": [cursor_info]}))

            self.cursor_info = cursor_info

        return

        # TODO: remove this?
        if not selection == self.last_selection:
            ok, start, end = selection
            if start > end:
                start, end = end, start
            print(f"[REToolSync] range selection: ({ok}, {hex(start)}, {hex(end - 1)})")
            self.last_selection = selection

        cursor = get_cursor()
        if not cursor == self.last_cursor:
            print(f"[REToolSync] sending cursor change {hex(self.last_cursor)} -> {hex(cursor)}")
            self.last_cursor = cursor

    def connect_and_read(self):
        endpoint = os.environ.get("RETOOLSYNC_ENDPOINT", "127.0.0.1:6969")
        request = tornado.httpclient.HTTPRequest(f"ws://{endpoint}/REToolSync", headers={"User-Agent": f"REToolSync IDA {os.getpid()}"})
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

    def on_message(self, message: str):
        if message is None:
            print("[REToolSync] Disconnected, reconnecting in 3 seconds...")
            self.periodic_cb.stop()
            self.io_loop.call_later(3, self.connect_and_read)
            return

        self.num_messages += 1

        msg: dict = json.loads(message)
        request = msg.get("request", None)
        if request == "goto":
            address = int(msg["address"], 16)
            print(f"[REToolSync] Goto: {hex(address)}")
            goto_address(address)
        else:
            print(f"[REToolSync] Unsupported message: {message}")

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
        QtWidgets.QApplication.processEvents()
        if timeout is not None and iteration_timeout * iterations >= timeout:
            return False
        iterations += 1

# jump to cursor: ida_kernwin.jumpto
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

# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    wanted_name = "REToolSync"
    wanted_hotkey = ""
    comment = "Tool for collaborative reverse engineering"
    help = ""

    def init(self):
        self.service = Service()
        self.service.start()
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.service.stop()

    def run(self, arg):
        self.service.start()

def PLUGIN_ENTRY():
    return my_plugin_t()
