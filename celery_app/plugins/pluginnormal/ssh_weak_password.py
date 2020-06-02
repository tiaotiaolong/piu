import paramiko

from celery_app.utils.utils import insert_vuln_db

#ssh 弱口令
plugin_id=61
default_port_list=[22]


def check(host, port=22):
    user_list = ['root', 'admin', 'test']
    paramiko.util.logging.getLogger('paramiko.transport').addHandler(paramiko.util.logging.NullHandler())
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    except:
        ssh.close()
        return False
    for user in user_list:
        for passwd in ['notapass!', 'root', 'root1234', 'test123', '123456', 'toor', 'root123']:
            try:
                timeout = 3

                ssh.connect(host, port, user, passwd, timeout=timeout, allow_agent=False, look_for_keys=False)
                if passwd == 'notapass!':
                    ssh.close()
                    return False
                target = '{}:{}'.format(host, port)
                ssh.close()
                insert_vuln_db(host, target, '{} {}'.format(user, passwd), plugin_id)
                return True, host, target, '{} {}'.format(user, passwd)
            except Exception as e:
                e = str(e)
                if "Unable to connect" in e or "timed out" in e or "Bad authentication type" in e:
                    ssh.close()
                    return False
    return False

