from snap7.client import Client

SERVER_IP = '127.0.0.100'
SERVER_PORT = 102

client = Client()
client.connect('127.0.0.100', 0, 2, SERVER_PORT)

try:
    print(client.get_plc_datetime())
    client.get_cpu_info()
    print(client.list_blocks())
    print(str(client.db_read(1, 0, 100)))
    client.db_write(1, 0, bytearray(b"HELLO, SERVER!"))
    print(str(client.db_read(1, 0, 100)))
    client.disconnect()
    client.plc_stop()
except RuntimeError as ex:
    print(ex)
