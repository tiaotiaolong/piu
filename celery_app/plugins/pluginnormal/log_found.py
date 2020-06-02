import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#通达 OA 系统 SQL 注入漏洞
plugin_id=86
default_port_list=web_port_short

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    log_files = ['debug.log',
                 'web.log',
                 'app.log',
                 'init.log',
                 'test.log',
                 'install.log',
                 'api.log', 'access.log', 'user.log', 'deploy.log', 'error.log',
                 'npm-debug.log']
    php_paths = ['app/', 'application/', 'log/', '']
    uris = ['/{}{}'.format(php_path, log_file) for php_path in php_paths for log_file in log_files]
    try:

        requests.packages.urllib3.disable_warnings()
        targets = ['{}{}'.format(target, uri) for uri in uris]

        check_error_response = requests.head('{}/loadg/biu404.log'.format(target), timeout=7)
        if check_error_response.status_code != 200:
            with requests.Session() as session:
                for target in targets:
                    response = session.head(target, timeout=7)
                    if response.status_code in [200, 301, 302] and response.url == target and session.head(
                            target.replace('.log', '/abc.log'), timeout=7).status_code not in [200, 301, 302]:
                        response = session.get(target, timeout=7)
                        content_type = str(
                            response.headers.get('Content-Type')) + (
                                           response.headers.get('content-type'))
                        if response.headers.get(
                                'Content-Length') > 10 and '<div' not in response.text.lower() and 'html>' not in response.text and 'json' not in content_type and 'html' not in content_type:
                            output = response.text
                            insert_vuln_db(host, target, output, plugin_id)
                            return True, host, target, output
    except:
        return False
    return False

