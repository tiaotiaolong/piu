import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#通达 OA 系统 SQL 注入漏洞
plugin_id=52
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/doc.pdf', '/help.pdf', '/wendang.pdf', '/api.pdf', '/web.pdf',
            '/dev.pdf', '/bangzhu.pdf', '/kaifa.pdf', '/帮助.pdf', '/说明.pdf', '/手册.pdf']
    hits = ['application/pdf']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.head(target, timeout=7, verify=False)

                for hit in hits:
                    if hit in str(response.headers.get('content-type')) and response.status_code in [200]:
                        output = response.headers
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

