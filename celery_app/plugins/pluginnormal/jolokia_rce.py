import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_long

#jolokia RCE
plugin_id=50
default_port_list=web_port_long


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/jolokia/list', '/actuator/jolokia/list']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.head(target, timeout=7)
                if response.status_code in [302, 200]:
                    response = session.get(target, timeout=7)
                    if 'ch.qos.logback.classic.jmx.JMXConfigurator' in response.text:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

