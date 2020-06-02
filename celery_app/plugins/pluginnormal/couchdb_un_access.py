import requests

from celery_app.utils.utils import insert_vuln_db


#Redis 未授权访问
plugin_id=56
default_port_list=[5984]

def check(host, port=5984):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/_session']
    hits = ['"roles":["_admin"]}']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.json()
                        insert_vuln_db(host, target, "", plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

