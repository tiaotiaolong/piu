import requests
import re

from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_long

#通达 OA 系统 SQL 注入漏洞
plugin_id=73
default_port_list=web_port_long


def get_token(url):
    result = re.findall('<input type="hidden" name="token" value="(\w+)" />', requests.get(url, timeout=10).text)
    if result:
        return result[0]
    return False


def is_phpmyadmin(url):
    return 'phpMyAdmin' in requests.get(url, timeout=10).text


def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)

    urls = [target, '{}/phpmyadmin/index.php'.format(target)]
    try:
        for url in urls:
            if not is_phpmyadmin(url):
                continue
            simple_passwords = ['', '123', '1234', '12345', '123456', '!@#', '1111', '111', '666', '1314']
            simple_users = ['', 'root', 'test', 'admin', 'server', 'password', 'mysql', 'ceshi', 'mima',
                            host.split('.')[0]]
            passwords = ['{}{}'.format(user, password) for user in simple_users for password in simple_passwords]
            for user in ['root', 'test', 'server', 'ceshi']:
                for pwd in passwords:
                    token = get_token(url)
                    if not token:
                        return False
                    data = {
                        "pma_username": user,
                        "pma_password": pwd,
                        "server": 1,
                        "token": token
                    }
                    requests.packages.urllib3.disable_warnings()
                    response = requests.post(url, data, timeout=7, headers={'Cookie': "pma_lang=zh_CN"})
                    if 'login_form' in response.text:
                        continue
                    elif response.status_code == 200 and 'db_structure.php' in response.text:
                        output = "用户名：{}\t 密码：{}".format(user, pwd)
                        target = url
                        insert_vuln_db(host, target, output, plugin_id)
                        return True, host, target, output
    except:
        return False
    return False

