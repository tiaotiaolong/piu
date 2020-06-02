import requests

from celery_app.utils.utils import insert_vuln_db


#Hadoop Yarn REST API未授权漏访问
plugin_id=78
default_port_list=[8088]

def check(host, port=8088):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/ws/v1/cluster/apps/new-application']
    hits = ['javaClassName>javax.ws.rs.WebApplicationException']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]

        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.json()
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

