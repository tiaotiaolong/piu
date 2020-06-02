import socket
from celery_app.utils.utils import insert_vuln_db
# from celery_app.config.config import web_port_short

#Redis 未授权访问
plugin_id=54
default_port_list=[6379]

def check(host, port=6379):
    try:
        with socket.create_connection((host, port), timeout=5) as conn:
            conn.send(b"INFO\r\n")
            response = str(conn.recv(2048), 'utf-8', 'ignore')
            if 'redis_version' in response:
                target = "{}:{}".format(host, port)
                insert_vuln_db(host, target, "", plugin_id)
                return True, host, target, response
            elif "Authentication" in response:
                return False
    except:
        return False

