from ctypes import *
import os
import socket
import platform
from bloodyAD import utils

LOG = utils.LOG

class ProxyBypass():
    proxy_connect = None
    
    def __init__(self):
        proxy_detected = 'LD_PRELOAD' in os.environ and 'proxychains' in os.environ['LD_PRELOAD']
        LOG.info("[*] Connection to Neo4j")
        if not proxy_detected:
            LOG.info("[*] No proxy detected")
            return
        supported_platform = platform.system() in ["Darwin", "Linux"]
        if not supported_platform:
            LOG.warning(f"[-] Proxy detected but {plateform.system()} is not currently supported. Please raise an issue on the Github repo")
            return
        
        self.proxy_connect = socket.socket.connect

        socket.socket.connect = real_connect
        LOG.info("[+] Proxy bypass enabled for Neo4j connection")
    
    def disable(self):
        if self.proxy_connect:
            socket.socket.connect = self.proxy_connect
            LOG.info("[+] Proxy bypass disabled")


class c_addrinfo(Structure):
    pass
c_addrinfo._fields_ = [
    ('ai_flags', c_int),
    ('ai_family', c_int),
    ('ai_socktype', c_int),
    ('ai_protocol', c_int),
    ('ai_addrlen', c_size_t),
    ] + ([
        ('ai_canonname', c_char_p),
        ('ai_addr', POINTER(c_sockaddr_in)),
    ] if platform.system() == 'Darwin' else [
        ('ai_addr', c_void_p),
        ('ai_canonname', c_char_p),
    ]) + [
        ('ai_next', POINTER(c_addrinfo)),
]

def real_connect(sock_obj, addro):
    libc = CDLL('libc.so.6')
    get_errno_loc = libc.__errno_location
    get_errno_loc.restype = POINTER(c_int)
    def errcheck(ret, func, args):
        if ret == -1:
            e = get_errno_loc()[0]
            raise OSError(e)
        return ret

    # addr = c_sockaddr_in(sock_obj.family, c_ushort(socket.htons(addro[1])), (c_byte *4)(*[int(i) for i in addro[0].split('.')]))
    # size_addr = sizeof(addr)
    c_getaddrinfo = libc.getaddrinfo
    c_getaddrinfo.errcheck = errcheck
    presult = POINTER(c_addrinfo)()
    hints = c_addrinfo()
    hints.ai_family = sock_obj.family
    hints.ai_socktype = sock_obj.type
    hints.ai_flags = 0
    hints.ai_protocol = sock_obj.proto
    c_getaddrinfo(addro[0].encode('utf-8'), str(addro[1]).encode('utf-8'), byref(hints), byref(presult))

    # Wait until DB response
    blocking = sock_obj.getblocking()
    sock_obj.setblocking(True)

    c_connect = libc.connect
    c_connect.errcheck = errcheck
    c_connect(sock_obj.fileno(), c_void_p(presult.contents.ai_addr), presult.contents.ai_addrlen)

    libc.freeaddrinfo(presult)

    sock_obj.setblocking(blocking)

# class c_sockaddr_in(Structure):
#     _fields_ = [
#         ('sa_family', c_ushort),
#         ('sin_port', c_ushort),
#         ("sin_addr", c_byte * 4),
#         ("__pad", c_byte * 8)
#     ]