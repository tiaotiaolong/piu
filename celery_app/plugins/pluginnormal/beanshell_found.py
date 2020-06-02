import requests

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#检测到 BeanShell
plugin_id=77
default_port_list=web_port_short


def check(host, port=1234):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/remote/awtconsole.html', '/remote/jconsole.html', '/bsh.servlet.BshServlet',
            '/weaver/bsh.servlet.BshServlet', '/weaveroa/bsh.servlet.BshServlet', '/oa/bsh.servlet.BshServlet']
    hits = ['BeanShell Remote Session', 'BeanShell Test Servlet']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.text
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False

