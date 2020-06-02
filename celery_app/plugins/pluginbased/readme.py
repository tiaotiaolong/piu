import requests
from app import pa_vuln,pa_domain
from celery_app.utils.utils import get_current_time,get_random_code
from celery_app.config.config import web_port_short

#readme 插件 用来检测http协议和https协议是否存在readme文件，返回的是一个列表，第一个元素是http的结果，第二个是https的
#如果2个协议都没有漏洞的话返回[False,False]
#如果都有的话是[(True,主机,内容),(True,主机,内容)]

default_port_list=web_port_short

headers={"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"}

def check(host,port=80):
    results = []
    uris = ['readme.md', 'README.MD', 'readme.MD', 'README.md']

    if port==443:
        scheme='https'
    else:
        scheme='http'

    target = "{0}://{1}:{2}/".format(scheme, host,port)

    try:
        for uri in uris:
            url=target+uri
            requests.packages.urllib3.disable_warnings()
            response=requests.get(url,headers=headers,verify=False,timeout=7)
            if response.status_code == 200 and response.headers.get('Content-Type') in ['application/octet-stream','text/markdown']:
                if len(response.text) and response.text[0] not in ['<','{','[']:
                    output=response.text
                    result=(True,scheme,host,url,output)
                    results.append(result)

    except Exception as e:
        pass

    #入库
    if len(results)>0:
        for info in results:
            if info:
                pa_vuln.insert({"host":info[2],"vuln_proof":info[4],"vuln_url":info[3],"plugin_id":1,"vuln_id":get_random_code(),"plugin_info":"用来探测网站是否存在readme文件","add_time":get_current_time()})
    return results


# print(check("check.newmine.net",80))
