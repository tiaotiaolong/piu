import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#RabbitMQ Management Guest账号弱口令
plugin_id=88
default_port_list=[15672]

def check(host, port=15672):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/api/vhosts']
    hits = ['messages_unacknowledged']

    headers = {"authorization": "Basic Z3Vlc3Q6Z3Vlc3Q="}

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, headers=headers, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.json()
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

