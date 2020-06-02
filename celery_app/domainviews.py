from flask import Blueprint,request
from .tasks import get_sub_domain_task
from app import pa_domain
from .utils.utils import get_current_time,insert_taskid_db

domain_blueprint = Blueprint("domain", __name__, url_prefix='/domain')


#添加域名
@domain_blueprint.route('/adddomain')
def adddomain():
    domain = request.args.get("domain")
    #如果域名已经添加过，就不需要添加了
    if(pa_domain.find_one({"domain":domain})):
        return {"code":201,"msg":"domain have added"}

    #添加域名和添加时间 子域名扫描状态 和ip端口扫描状态
    pa_domain.insert_one({"domain":domain,"add_time":get_current_time(),"task_subdomain_process":0,"task_ipscan_process":0})

    result={"code":200,"msg":"add success"}
    return result


#对已经添加的域名进行子域名爆破任务
@domain_blueprint.route('/brutesubdomain')
def brute_sub_domain():
    domain = request.args.get("domain")
    if not (pa_domain.find_one({"domain": domain})):
        return {"code": 201, "msg": "no domain you want,please add it first"}

    # 调用Cerely后台 进行子域名批量获取,获取任务id
    r = get_sub_domain_task.delay(domain)
    # 任务库入库
    insert_taskid_db({"task_id": r.task_id, "add_time": get_current_time(),"task_type":"brute_subdomain","task_info": "对域名{0}进行二级域名扫描探测".format(domain)})

    result = {"code": 200, "msg": "add brute subdomain tasks success"}
    return result


#获取域名总数
@domain_blueprint.route('/getdomainnum')
def get_domain_num():
    return {"domain_num":pa_domain.find({}).count()}


#获取域名列表
#index为起始索引 offset为数量
#返回域名的添加时间，domain等信息
@domain_blueprint.route('/getdomainlist')
def get_domain_list():
    result=[]
    tmp={}
    domain_index = int(request.args.get("index"))
    domain_offset = int(request.args.get("offset"))
    cursor=pa_domain.find().skip(domain_index).limit(domain_offset)
    for document in cursor:
        tmp['domain']=document['domain']
        tmp['add_time']=document['add_time']
        tmp['task_subdomain_process']=document['task_subdomain_process']
        tmp['task_ipscan_process']=document['task_ipscan_process']

        result.append(tmp)
        tmp={}

    return {"domain_list":result}







