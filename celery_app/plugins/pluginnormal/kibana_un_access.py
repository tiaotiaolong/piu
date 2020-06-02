import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Kibana 存在未授权访问
plugin_id=87
default_port_list=[5601]

def check(host, port=5601):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = [
        '/elasticsearch/404adqweqw/_mapping/field/*?_=1569226048367&ignore_unavailable=false&allow_no_indices=false&include_defaults=true',
        '/api/saved_objects/_find?type=index-pattern&fields=title&per_page=10']
    hits = ['"type":"index_not_found_exception","reason', '"saved_objects":[']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [404, 200]:
                        output = response.json()
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

