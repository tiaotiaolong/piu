import requests
import json

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Redis 未授权访问
plugin_id=57
default_port_list=web_port_short


def checkLock(content):
    content = json.dumps(content)

    files = {'lock': ('composer.lock', content)}
    check_response = requests.post('https://security.symfony.com/check_lock', files=files,
                                   headers={'Accept': 'application/json'})
    # print(check_response.json())
    if check_response.json().get('error'):
        return []
    else:
        vulnerabilities = [
            {'package': vulnerability, 'version': check_response.json().get(vulnerability).get('version'),
             'advisories': check_response.json().get(vulnerability).get('advisories')} for vulnerability in
            check_response.json().keys()]
        return vulnerabilities


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ["/composer.lock"]
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7)
                if 'name' in response.json().get('packages')[0].keys():
                    check_result = checkLock(response.json())
                    if len(check_result):
                        output = check_result
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

