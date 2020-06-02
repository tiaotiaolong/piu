import requests
from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#海视威康 DNVRS 弱口令
plugin_id=67
default_port_list=web_port_short



def is_hikvision(target):
    resp = requests.head('{}/PSIA/Custom/SelfExt/userCheck'.format(target))
    return resp.status_code == 200 and resp.headers.get('Server') == 'DNVRS-Webs' and resp.headers.get(
        'Content-Length') == '137'


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    try:
        if not is_hikvision(target):
            return False
        target = '{}/PSIA/Custom/SelfExt/userCheck'.format(target)
        users = ['admin']
        passwords = ['12345', '123456', '1234567', '00000']
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for password in passwords:
                for user in users:
                    response = session.get(target, timeout=7, verify=False, auth=(user, password))
                    if '<statusValue>200</statusValue>' in response.text:
                        output = '用户名:{}\t密码:{}\n{}'.format(user, password, response.text)
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except:
        return False
    return False

