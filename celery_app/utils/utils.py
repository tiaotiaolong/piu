import time
from app import pa_taskid,pa_plugin,pa_vuln,pa_sub_domain,pa_ip
from celery_app.config.config import DNS_LOG_HOST,VTEST_HOST,VTEST_PORT
import string
import random
import requests


#获取当前时间
def get_current_time():
    return time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))


#创建任务 taskid入库
def insert_taskid_db(content):
    pa_taskid.insert(content)

#通过plugin_id查找plugin_name plugin_info等信息
def get_plugin_name_by_id(id):
    result=[]
    cursor=pa_plugin.find({"plugin_id":id})
    for document in cursor:
        result.append((document['plugin_name'],document['plugin_info']))

    if(len(result)==1):
        return result[0]

    return ("未找到插件名","未找到插件描述")

#生成32位随机id
def get_random_code():
    return ''.join(random.sample(string.ascii_lowercase + string.digits , 32))


#pa_vuln 漏洞入库
def insert_vuln_db(host,target,output,plugin_id):
    pa_vuln.insert({"host": host, "vuln_proof": output, "vuln_url": target, "plugin_id": plugin_id, "vuln_id": get_random_code(),"add_time": get_current_time()})


#根据子域名获取开放端口列表
def get_ports_list_by_domain(sub_domain):
    ports_result=[]
    try:
        sub_domain_ip=pa_sub_domain.find_one({"subdomain":sub_domain})['sub_domain_ip']

        print(sub_domain_ip)
        for ip in sub_domain_ip:
            port_list=pa_ip.find_one({"ip":ip})['port']
            ports_result.extend(port_list)

    except Exception as e:
        return []
    return list(set(ports_result))


#针对无回显的漏洞，生成6位subdomain和dns_payload
def get_dns_payload():
    subdomain=''.join(random.sample(string.ascii_lowercase + string.digits, 6))
    dns_payload=subdomain+'.'+DNS_LOG_HOST
    return subdomain,dns_payload


#校验dns_record
def have_record(sub_domain):
    vtest_url="http://"+VTEST_HOST+":"+VTEST_PORT+"/api/dns?token=0409451d31623c9053fb8d41a60979ca&q="+sub_domain
    response=requests.get(vtest_url)
    if "rows" in response.text:
        return True
    return False








