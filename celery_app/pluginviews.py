from flask import Blueprint,request
from .tasks import check_plugins_task
from app import pa_domain,pa_taskid,pa_plugin
from celery_app.utils.utils import get_current_time,insert_taskid_db


pluginscan_blueprint = Blueprint("pluginscan", __name__, url_prefix='/pluginscan')

@pluginscan_blueprint.route('/scan',methods=['POST'])
#传入一个插件id的列表，一个二级域名的列表，开始对每一个二级域名进行每一个插件的扫描
def plugins_scan_by_subdomain():
    if request.method=="POST":
        json_data=request.get_json()
        plugins_id_list=json_data['plugins_id_list']
        domains_list=json_data['domains_list']

        #对domains_list做空白字符处理
        if domains_list[-1]=="":
            domains_list.pop(-1)


        # 调用celery任务
        r=check_plugins_task.delay(plugins_id_list,domains_list)
        # taskid入库
        insert_taskid_db({"task_id":r.task_id,"add_time":get_current_time(),"task_type":"pluginscan","plugin_list":plugins_id_list,"domain_list":domains_list,"task_info":"对{0}等{1}个域名进行插件扫描,插件id为{2}等{3}个".format(domains_list[0],len(domains_list),plugins_id_list[0],len(plugins_id_list))})

        return {"code": 200, "msg": "plugin scan task success"}
    return {"code": 201, "msg": "POST method need"}

#传入一个一级域名，对数据库内该一级域名的所有二级域名进行每一个插件的扫描
@pluginscan_blueprint.route('/scanbydomain',methods=['POST'])
def plggins_scan_by_maindomain():
    if request.method=="POST":
        #获取POST过来的数据
        json_data = request.get_json()
        plugins_id_list = json_data['plugins_id_list']
        domain = json_data['domain']
        #声明二级域名的列表

        subdomain_list=[]
        #通过domain获取所有的该domain的二级域名
        index=pa_domain.find_one({"domain":domain})
        if index:
            subdomain=index['subdomain']
            for sub in subdomain:
                subdomain_list.append(sub["sub_domain"])
        #没有在数据库中找到该主域名
        else:
            return {"code": 202, "msg": "did not find domain {0}".format(domain)}

        if len(subdomain_list)>0:
            # 调用celery任务,并且获取任务id
            r=check_plugins_task.delay(plugins_id_list, subdomain_list)
            #记录任务id
            insert_taskid_db({"task_id":r.task_id,"add_time":get_current_time(),"task_type":"pluginscan","plugin_list":plugins_id_list,"domain_list":subdomain_list,"task_info":"对{0}域名下的{1}个子域名进行插件扫描,插件id为{2}等{3}个".format(domain,len(subdomain_list),plugins_id_list[0],len(plugins_id_list))})


        return {"code": 200, "msg": "plugin scan task success"}
    return {"code": 201, "msg": "POST method need"}


#获取插件总数
@pluginscan_blueprint.route('/getpluginnum')
def get_plugin_num():
    return {"plugin_num": pa_plugin.find({}).count()}



#获取插件列表信息 offset index
@pluginscan_blueprint.route('/getpluginlist')
def get_plugin_info():
    result = []
    domain_index = int(request.args.get("index"))
    domain_offset = int(request.args.get("offset"))
    cursor=pa_plugin.find().skip(domain_index).limit(domain_offset)
    for document in cursor:
        document.pop('_id')
        result.append(document)

    return {"plugin_list":result}


#添加新的插件 输入插件名，插件描述
@pluginscan_blueprint.route('/addplugin',methods=['POST'])
def add_plugin():

    if request.method=="POST":
        # 获取POST过来的数据
        json_data = request.get_json()
        plugin_name = json_data['plugin_name']
        plugin_info = json_data['plugin_info']
        plugin_type = json_data['plugin_type']
        vuln_type  = json_data['vuln_type']
        vuln_level = json_data['vuln_level']


        #获取plugid_id
        plugin_id=pa_plugin.find({}).count()+1

        pa_plugin.insert({"plugin_id":plugin_id,"plugin_name":plugin_name,"plugin_info":plugin_info,
                          "plugin_type":plugin_type,"vuln_type":vuln_type,"vuln_level":vuln_level})
        return {"code":200,"msg":"add plugin success"}
    return {"code": 201, "msg": "method invalid"}


#根据插件id 获取插件信息
@pluginscan_blueprint.route('/getplugininfobyid')
def get_plugin_info_bby_id():
    plugin_id=int(request.args.get("plugin_id"))
    result=pa_plugin.find_one({"plugin_id":plugin_id})
    result.pop("_id")
    return result


#修改属性
@pluginscan_blueprint.route('/addtype')
def addtype():
    plugin_id = int(request.args.get("plugin_id"))


    # temp=pa_plugin.find_one({"plugin_id":plugin_id})
    # print(temp)
    # temp["plugin_type"]="base"

    for i in range(41):
        pa_plugin.update_one({"plugin_id":i},{"$set":{"plugin_type":"base"}})
    return {"msg":200}


















