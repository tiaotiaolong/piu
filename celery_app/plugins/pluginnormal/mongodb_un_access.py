import binascii
import re
import socket

from celery_app.utils.utils import insert_vuln_db


#Redis 未授权访问
plugin_id=55
default_port_list=[27017]


def check(host, port=27017):
    try:
        with socket.create_connection((host, port), timeout=5) as conn:
            data = binascii.a2b_hex(
                "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")

            conn.send(data)
            response = str(conn.recv(2048), 'utf-8', 'ignore')
            if "ismaster" in response:
                list_databases_data = binascii.a2b_hex(
                    "4a0000001100000000000000d40700000400000061646d696e2e24636d6400000000000100000023000000106c6973744461746162617365730001000000086e616d654f6e6c79000100")
                conn.send(list_databases_data)
                response = str(conn.recv(12048), 'utf-8', 'ignore')
                if "databases" in response:
                    target = "{}:{}".format(host, port)
                    dbs = re.findall('name.*?(\w+)\x00', response)
                    output = '\n'.join(dbs)
                    insert_vuln_db(host, target, output, plugin_id)
                    return True, host, target, output
    except:
        return False

