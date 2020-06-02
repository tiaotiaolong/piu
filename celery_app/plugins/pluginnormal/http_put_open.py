import requests
import time
import random

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#通达 OA 系统 SQL 注入漏洞
plugin_id=82
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    timestamp = int(time.time())
    target = '{}/{}.txt'.format(target, timestamp)
    try:
        file_content = '{}-{}'.format(random.random(), timestamp)
        requests.packages.urllib3.disable_warnings()
        requests.put(target, json={'data': file_content}, timeout=7)
        response = requests.get(target, timeout=7)
        if response.text == file_content:
            output = '目标开启 http PUT'
            insert_vuln_db(host, target, output, plugin_id)
            return True, host, target, output
        else:
            return False
    except:
        return False

