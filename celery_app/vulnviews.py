from flask import Blueprint,request
from app import pa_vuln
import time
import re
from celery_app.utils.utils import get_plugin_name_by_id

vuln_blueprint = Blueprint("vuln", __name__, url_prefix='/vuln')


##获取漏洞列表，index为起始索引 offset为数量
@vuln_blueprint.route('/vulnlist')
def get_vuln_list():
    result = []
    tmp = {}
    domain_index = int(request.args.get("index"))
    domain_offset = int(request.args.get("offset"))
    cursor = pa_vuln.find().sort([('_id', -1)]).skip(domain_index).limit(domain_offset)
    for document in cursor:
        tmp['vuln_url']=document['vuln_url']
        tmp['add_time']=document['add_time']
        tmp['vuln_id']=document['vuln_id']

        #获取插件信息
        (name,info)=get_plugin_name_by_id(document['plugin_id'])
        tmp['plugin_name'] =name
        tmp['plugin_info'] =info

        result.append(tmp)
        tmp={}

    return {"vuln_list":result}



@vuln_blueprint.route('/getvulnnum')
def get_vuln_num():
    return {"vuln_num": pa_vuln.find({}).count()}


#获取今天新增漏洞数量
@vuln_blueprint.route('/getvulnnumtoday')
def get_vuln_num_today():
    today=time.strftime('%Y-%m-%d',time.localtime(time.time()))
    count=pa_vuln.find({'add_time':{ '$regex' : today+'(.*)'}}).count()
    return {'vuln_num_today':count}

#获取本月新增漏洞数量
@vuln_blueprint.route('/getvulnnummonth')
def get_vuln_num_week():
    today=time.strftime('%Y-%m',time.localtime(time.time()))
    count=pa_vuln.find({'add_time':{ '$regex' : today+'(.*)'}}).count()
    return {'vuln_num_month':count}


#根据漏洞ID获取漏洞详情
@vuln_blueprint.route('/getvulninfo')
def get_vuln_info():
    vuln_id=request.args.get("vuln_id")
    vuln=pa_vuln.find_one({"vuln_id":vuln_id})

    vuln.pop("_id")
    return vuln





