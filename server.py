import time

from snap7.server import Server
from snap7.server import logger
from snap7 import types

SERVER_IP = '127.0.0.100'
SERVER_PORT = 102


def mainloop(tcp_port):
    server = Server()
    size = 100

    DBdata = (types.wordlen_to_ctypes[types.S7WLByte] * size)()
    PAdata = (types.wordlen_to_ctypes[types.S7WLByte] * size)()
    TMdata = (types.wordlen_to_ctypes[types.S7WLByte] * size)()
    CTdata = (types.wordlen_to_ctypes[types.S7WLByte] * size)()

    for i in range(size):
        DBdata[i] = i

    server.register_area(types.srvAreaDB, 1, DBdata)
    server.register_area(types.srvAreaPA, 1, PAdata)
    server.register_area(types.srvAreaTM, 1, TMdata)
    server.register_area(types.srvAreaCT, 1, CTdata)

    server.start_to('127.0.0.100', tcpport=tcp_port)
    while True:
        while True:
            event = server.pick_event()
            if event:
                logger.info(server.event_text(event))
            else:
                break


mainloop(SERVER_PORT)
