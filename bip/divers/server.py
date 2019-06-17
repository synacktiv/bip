from bip.base import * #get_addr_by_name, get_name_by_addr, absea, relea
#from bip.models import *

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from SocketServer import ThreadingMixIn
import threading
import argparse
import re
import cgi
import socket
import os
from json import loads, dumps

from ida_kernwin import MFF_READ, execute_sync

from idc import GetInputFile

def to_dict(self):
    """
        Recuperate information about this field as a dictionnary.
        Field of the dictionnary are:

        * ``name`` (``str``): the name of this field.
        * ``offset`` (``int``): the offset of this field.
        * ``size`` (``int``): the size of this field.
        * ``comment`` (``str``): the comment of this field, empty string if no comment.
        * ``type`` (``str``): the type of this field.

        :rtype: dict()
    """
    return {
        'name':self.name,
        'offset':self.offset,
        'size':self.size,
        'comment':self.comment,
        'type':str(self.type)
    }
    

def complete_symbol(data):
    """
        (name:symbol_name_filter) -> (offset:offset)
    """
    if 'name' not in data:
        print "[!] Malformed input json in search_symbol, attribute name missing"
        return {}

    funcs = [f.name for f in IdaFunction.get_by_prefix(str(data['name']))]

    return {'symbols': funcs}

def search_symbol(data):
    """
        {name:symbol_name_filter} -> {offset:offset}
    """
    if 'name' not in data:
        print "[!] Malformed input json in search_symbol, attribute name missing"
        return {}
    
    ea = get_addr_by_name(str(data['name']))
    return {'offset':ea}

def search_offset(data):
    """
        {offset:offset} -> {function:func_name, offset:offset}
    """
    if not 'offset' in data:
        name, offset = '', 0
    else:
        name, offset = get_name_by_addr(data['offset'])
    return {'function':name, 'offset':offset}

def get_module(data):
    return {'module': GetInputFile()}

def get_breakpoints(data):
    bpts = bpt_vec_t()
    get_grp_bpts(bpts, 'Default')
    return [relea(b.ea) for b in bpts]

def rpc_get_struct(data):
    """
        {struct_name:struct_name} -> {comment: comment, fields: [{field_name:field_name, type:type}]}
    """
    try:
        s = Struct.get(str(data['struct_name']))
    except ValueError:
        return {}

    return {'fields': [f.to_dict() for f in s.members], 'size': s.size}

def rpc_goto(data):
    if not 'offset' in data:
        return
    
    Jump(relea(data['offset']))
    

def handle_rpc(data):
    if not 'function' in data or not 'args' in data:
        return {'error': 'missings args in rpc call'}

    modules = [bip.utils, idc, idautils, idaapi]

    for m in modules:
        if hasattr(m, data['function']) and callable(getattr(m, data['function'])):
            try:
                out = getattr(m, data['function'])(*data['args'], **data['kwargs'])
                return {'returned':out}
            except Exception as e:
                return {'exception':'%s %s' % (e.__class__.__name__, e)}
    return {'exception': 'unknown function %s' % data['function']}

handlers = {
    '/search_symbol': search_symbol,
    '/search_offset': search_offset,
    '/get_module': get_module,
    '/get_struct': rpc_get_struct,
    '/goto': rpc_goto,
    '/get_breakpoints': get_breakpoints
}


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path in handlers:
            ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
            if ctype == 'application/json':
                length = int(self.headers.getheader('content-length'))
                data = loads(self.rfile.read(length))
                # needs to execute the handlers in the main thread to avoid fails
                out = dumps(bip_exec_sync(handlers[self.path], data))
            else:
                out = {}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(out)
        else:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

    def shutdown(self):
        self.socket.close()
        HTTPServer.shutdown(self)

class SymbolServer():
    def __init__(self, host="0.0.0.0", port=0):
        self.started = False
        
        if not port:
            port = get_port()

        self.host = host
        self.port = port
        self.server = ThreadedHTTPServer((host,port), HTTPRequestHandler)

    def start(self):
        if self.started:
            print "Server already started"
            print "Listening on %s:%d" % (self.host, self.port)        
            return
        
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.started = True
        print "Listening on %s:%d" % (self.host, self.port)

    def waitForThread(self):
        self.server_thread.join()

    def stop(self):
        if not self.started:
            print "Server not started"
            return
        
        self.server.shutdown()
        self.waitForThread()


def get_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0)) # actually bind
    port = sock.getsockname()[1]
    sock.close()
    return port
