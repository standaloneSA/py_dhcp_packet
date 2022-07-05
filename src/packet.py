"""
The information is taken and interpreted from RFC2131 and RFC2132
https://www.ietf.org/rfc/rfc2131.txt
https://www.ietf.org/rfc/rfc2132.txt

Also, some ideas and code were taken from pyPXE and tmeiczin's pyDHCP

https://github.com/pypxe/PyPXE
https://github.com/tmeiczin/pydhcp/

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
"""

from ctypes import Union
import typing
import struct
import socket

big_format = ""

class packet:

    class types:
        BOOTREQUEST=1
        BOOTREPLY=2

    def __init__(
        self,
        op = typing.Optional[int]=None,
        htype = typing.Optional[int]=None,
        hlen = typing.Optional[int]=None,
        hops = typing.Optional[int]=None,
        xid = typing.Optional[int]=None,
        secs = typing.Optional[int]=None,
        flags = typing.Optional[bytearray]=None,
        ciaddr = typing.Optional[typing.Union[str, bytearray]]=None,
        yiaddr = typing.Optional[typing.Union[str, bytearray]]=None,
        siaddr = typing.Optional[typing.Union[str, bytearray]]=None,
        giaddr = typing.Optional[typing.Union[str, bytearray]]=None,
        chaddr = typing.Optional[typing.Union[str, bytearray]]=None,
        sname = typing.Optional[str]=None,
        file = typing.Optional[str]=None,
        options = typing.Optional(list)=None,
        in_bytes = typing.Optional[bytearray]=None,
    ):
        self.headers = {}
        if in_bytes is not None:
            # If we're passing in_bytes, then we have received a packet and we want to parse it.
            pass
        else:
            # If in_bytes isn't set, then assume that we want to take all of the other arguments
            # as header options
            self.headers = {
                "op": op,
                "htype": htype,
                "hlen": hlen,
                "hops": hops,
                "xid": xid,
                "secs": secs,
                "flags": flags,
                "ciaddr": ciaddr,
                "yiaddr": yiaddr,
                "siaddr": siaddr,
                "giaddr": giaddr,
                "chaddr": chaddr,
                "sname": sname,
                "file": file,
                "options": []
            }
            for option in options:
                self.headers["options"].append({
                    "code": option.getattr("code"),
                    "len": len(option.getattr("byteval")),
                    "byteval": option.getattr("byteval"),
                    })

        def to_bytes(self):
            # See the diagram of the packet at the top as well as 
            # the struct byte packing formats here:
            # https://docs.python.org/3/library/struct.html
            ret_bytes = struct.pack('!bbbb', self.op, self.htype, self.hlen, self.hops)
            ret_bytes += struct.pack('!i', self.xid)
            ret_bytes += struct.pack('!HH', self.secs, self.flags)
            ret_bytes += struct.pack('!i', self.ciaddr)
            ret_bytes += struct.pack('!i', self.yiaddr)
            ret_bytes += struct.pack('!i', self.siaddr)
            ret_bytes += struct.pack('!i', self.giaddr)
            ret_bytes += struct.pack('!16s', self.chaddr)
            ret_bytes += struct.pack('!64s', self.sname.encode('utf-8'))
            ret_bytes += struct.pack('!128s', self.file.encode('utf-8'))

            # magic cookie from the RFC
            ret_bytes += struct.pack('!BBBB', 99, 130, 83, 99) 

            for option in self.options:
                pass
            return ret_bytes

class DHCPREQUEST(packet):
    pass

class DHCPOFFER(packet):
    pass

class DHCPACK(packet):
    pass

class DHCPNACK(packet):
    pass

class DHCPDISCOVER(packet):
    pass
