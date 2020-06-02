from flask import Blueprint,request
from app import pa_domain,pa_ip
from .tasks import scan_ip_task
from celery_app.utils.utils import get_current_time,insert_taskid_db

ipscan_blueprint = Blueprint("ipscan", __name__, url_prefix='/ipscan')

#通过传入一个一级域名，对这个域名下的所有ip进行scan
@ipscan_blueprint.route('/scan')
def scan_ip():
    domain = request.args.get("domain")
    #在数据库搜索该domain的索引
    domain_index=pa_domain.find_one({"domain":domain})

    if domain_index:
        # 声明ip_list
        ip_list = []
        #获取整个domain所对应的ip
        for item in domain_index['subdomain']:
            for ip_s in item['ip']:
                ip_list.append(ip_s)

        #对ip_list去重
        ip_list=list(set(ip_list))

        #调用scan_ip 任务 传入主域名和对应的ip列表
        r=scan_ip_task.delay(domain,ip_list)
        # taskid入库
        insert_taskid_db({"task_id":r.task_id,"add_time":get_current_time(),"task_type":"ip_scan","ip_list":ip_list,"task_info":"对{0}域名下的{1}等{2}个ip进行端口扫描".format(domain,ip_list[0],len(ip_list))})

        return {"code":200,"msg":"添加扫描任务成功"}

    return {"code":201,"msg":"未找到该域名所对应ip"}



#获取ip总数
@ipscan_blueprint.route('/getipnum')
def get_ip_num():
    return {"ip_num":pa_ip.find({}).count()}


#获取ip列表,index为起始索引 offset为数量
@ipscan_blueprint.route('/getiplist')
def get_ip_list():
    result = []
    tmp = {}
    domain_index = int(request.args.get("index"))
    domain_offset = int(request.args.get("offset"))
    cursor = pa_ip.find().sort([('_id', -1)]).skip(domain_index).limit(domain_offset)
    for document in cursor:
        tmp['ip'] = document['ip']
        tmp['add_time'] = document['add_time']
        tmp['port'] = document['port']

        result.append(tmp)
        tmp = {}

    return {"ip_list": result}
