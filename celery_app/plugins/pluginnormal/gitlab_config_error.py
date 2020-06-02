
import requests
import re


from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_long

#GitLab 项目权限配置错误
plugin_id=72
default_port_list=web_port_long

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/explore/projects?group=&scope=&sort=updated_desc&tag=&visibility_level=']
    hits = ['dash-project-avatar', 'The project can be accessed without any authentication']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=7, verify=False)
                for hit in hits:
                    if hit in response.text:
                        gitlab_url = '{}://{}:{}'.format(scheme, host, port)
                        projects = ['{}{}'.format(gitlab_url,project) for project in re.findall('<a class="project" href="(.*?)">',response.text)]
                        output = 'GitLab 项目权限配置错误\nURL:\n{}\n配置错误的部分项目:\n{}'.format(target,'\n'.join(projects))
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False


