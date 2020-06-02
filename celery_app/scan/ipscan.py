
import masscan
from app import pa_ip,pa_domain
from celery_app.utils.utils import get_current_time


class MyScan:

    def __init__(self,ip_list,ports='21,22,25,80,443,3389,3306,8080'):
        self.ip_list=ip_list
        self.ports=ports
        self.mas=masscan.PortScanner()


    def scan(self):
        for ip in self.ip_list:
            try:
                self.mas.scan(ip, ports=self.ports, arguments='--max-rate 1000')
                self.save_scan_data()
            except Exception as e:
                pass



    def save_scan_data(self):
        data=self.mas.scan_result['scan']
        port_open_list=[]
        for key in data:

            for k in data[key]['tcp']:
                if(data[key]['tcp'][k]['state']=='open'):
                    port_open_list.append(k)

        #插入ip,如果插入的ip已经存在，则更新即可
        index=pa_ip.find_one({"ip": key})
        if index:
            #ip存在的话，只需要更新端口，并且增加扫描次数即可
            new_scaned_num=index['scaned_num']+1
            pa_ip.update_one({"ip":key},{"$set":{"port":port_open_list,"scaned_num":new_scaned_num}})

        else:
            #不存在的话，直接插入一个新的即可
            pa_ip.insert({"ip":key,"port":port_open_list,"add_time":get_current_time(),"has_scaned":True })


#对pa_domain 回馈 IPscan任务已经完毕 1代表已经执行过此任务
def save_ipscan_domaindb(domain):
    index=pa_domain.find_one({"domain":domain})
    if index:
        pa_domain.update_one({"domain":domain},{"$set":{"task_ipscan_process":1}})


def ip_scan(domain,ip_list):
    r=MyScan(ip_list)
    r.scan()

    save_ipscan_domaindb(domain)








