from . import celery
from .domain.SubDomainBrute import sub_domain_brute
from app import pa_plugin,pa_sub_domain,pa_ip
from .scan.ipscan import ip_scan
import importlib
from celery_app.utils.utils import get_plugin_name_by_id
from datetime import datetime
import queue
import threading


#基线插件路径
PLUGIN_BASE_DIR="celery_app.plugins.pluginbased"
#普通插件路径
PLUGIN_NORMAL_DIR="celery_app.plugins.pluginnormal"

#默认线程数
THREADS_NUM=10

#设置插件queue
SHARE_Q_PLUGINS=queue.Queue()

#线程停止的标志，为真的时候，所有线程立马停止
EXIT_FLAG=False

#设置队列的一个锁
queue_lock=threading.Lock()

#Celery 爆破子域名任务
@celery.task()
def get_sub_domain_task(domain):
    print("发现子域名任务开始")
    sub_domain_brute(domain,20)
    print("发现子域名任务结束")
    return True


#对ip进行扫描，扫描相应的端口，以及服务
@celery.task()
def scan_ip_task(domain,ip_list):
    print("ip扫描任务开始")
    ip_scan(domain,ip_list)
    print("ip扫描任务结束")
    return True

#对选取的插件和domain进行检测
@celery.task()
def check_plugins_task(plugins_id_list,domains_list):

    print("插件扫描任务开始")
    starttime = datetime.now()

    #设置线程列表
    threads=[]

    #创建线程
    for i in range(THREADS_NUM):
        thread=threading.Thread(name="thread-"+str(i),target=check_plugins_threads,args=(domains_list,))
        thread.start()
        threads.append(thread)


    # 把plugin_id 添加到队列中
    queue_lock.acquire()
    for plugin_id in plugins_id_list:
        SHARE_Q_PLUGINS.put(plugin_id)
    queue_lock.release()

    #如果队列不为空的话就主进程就在这等待，如果为空了的话就结束每一个子进程
    while not SHARE_Q_PLUGINS.empty():
        pass

    #设置标志为真，线程退出
    global EXIT_FLAG
    EXIT_FLAG = True

    # 等待每个线程结束
    for t in threads:
        t.join()

    overtime = datetime.now()
    print("插件扫描任务结束,总用时{0}s".format((overtime - starttime).seconds))
    return True


def check_plugins_threads(domains_list):

    # 考虑到短时间内多次对一个域名进行扫描 可能会触发某些未知的防护
    # 这个修改成先对插件进行遍历，然后对域名进行遍历
    global SHARE_Q_PLUGINS
    global EXIT_FLAG

    while not EXIT_FLAG:
        queue_lock.acquire()
        if not SHARE_Q_PLUGINS.empty():
            queue_lock.release()
            plugin_id=SHARE_Q_PLUGINS.get()
            #做一些准备工作
            plugin = get_plugin_name_by_id(plugin_id)
            plugin_name = plugin[0]
            plugin_info = plugin[1]
            print("线程{0}开始执行{1}插件,插件描述为{2}".format(threading.current_thread().name,plugin_name, plugin_info))
            starttime = datetime.now()

            pa_plugin_index = pa_plugin.find_one({"plugin_id": plugin_id})
            plugin_name = pa_plugin_index["plugin_name"]
            plugin_type = pa_plugin_index["plugin_type"]

            # 基线插件
            if plugin_type == "base":
                PLUGIN_DIR = PLUGIN_BASE_DIR
            elif plugin_type == "normal":
                PLUGIN_DIR = PLUGIN_NORMAL_DIR

            plugin_module = importlib.import_module("{0}.{1}".format(PLUGIN_DIR, plugin_name))
            for domain in domains_list:
                for port in plugin_module.default_port_list:
                    plugin_module.check(host=domain, port=port)
            overtime = datetime.now()
            print("线程{0}结束执行{1}插件,用时{2}s".format(threading.current_thread().name,plugin_name, (overtime - starttime).seconds))

        else:
            queue_lock.release()

















