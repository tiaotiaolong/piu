import requests

from celery_app.utils.utils import insert_vuln_db

#kubelet 允许匿名访问
plugin_id=79
default_port_list=[10250]


def check(host, port=10250):
    scheme = 'https'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/runningpods']
    hits = ['"kind":"PodList"']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.json()
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

