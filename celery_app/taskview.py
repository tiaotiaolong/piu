from flask import Blueprint,request
from .tasks import check_plugins_task,scan_ip_task
from app import pa_taskid
import time

# from run import celery

tasks_blueprint = Blueprint("task", __name__, url_prefix='/task')

#通过taskid获取任务状态
@tasks_blueprint.route('/info')
def get_tasks_info():
    task_id = request.args.get("taskid")
    res = check_plugins_task.AsyncResult(task_id)
    # print res.task_id
    return {"a":res.state}


#通过任务列表
@tasks_blueprint.route('/gettasklist')
def get_task_list():
    result = []
    tmp = {}
    domain_index = int(request.args.get("index"))
    domain_offset = int(request.args.get("offset"))
    cursor = pa_taskid.find().sort([('_id', -1)]).skip(domain_index).limit(domain_offset)
    for document in cursor:
        tmp['task_info'] = document['task_info']
        tmp['add_time'] = document['add_time']
        tmp['task_id'] = document['task_id']
        result.append(tmp)
        tmp = {}

    return {"task_list": result}


#获取任务数量
@tasks_blueprint.route('/gettasknum')
def get_task_num():
    return {"task_num": pa_taskid.find({}).count()}

#获取今日任务新增数量
@tasks_blueprint.route('/gettasknumtoday')
def get_task_num_today():
    today = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    count = pa_taskid.find({'add_time': {'$regex': today + '(.*)'}}).count()
    return {'task_num_today': count}



