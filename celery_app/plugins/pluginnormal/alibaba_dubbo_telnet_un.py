import socket
from celery_app.utils.utils import insert_vuln_db


#Alibaba Dubbo remoting telnetd 未授权访问
plugin_id=46
default_port_list=[80,443,1099,8080,6668,9200,7070,18101,6668,20000,20005,20800,20880,50002]

def check(host, port=20880):
    try:
        with socket.create_connection(address=(host, port), timeout=10) as conn:
            conn.send(b'\n')
            data = conn.recv(2014)
            if str(data.decode()) == 'dubbo>':
                conn.send(b'ls\n')
                data = conn.recv(2014)
                output = str(data.decode())
                conn.send(b'status -l\n')
                data = conn.recv(2014)
                output = '{}\n{}'.format(output, str(data.decode()))
                target = "{}:{}".format(host, port)
                insert_vuln_db(host, target, output, plugin_id)
                return True, host, target, output
            else:
                return False
    except:
        return False

