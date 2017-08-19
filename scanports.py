#coding: utf-8


import re
import os
import csv
import sys
import IPy
import nmap
import socket
import logging
import argparse
import threading
from Queue import Queue
from datetime import datetime

path = os.path.join(__file__,'log.txt')

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass


reload(sys)
sys.setdefaultencoding('utf-8')

socket.setdefaulttimeout(10)


DEFAULT_PORTS= '21,22,23,25,53,67,80,81,82,110,1433,1521,1526,3306,3389,4899,8580'
DEFAULT_PORTS += ',873'         # rsync default port
DEFAULT_PORTS += ',443,465,993,995' # ssl services port(https tcp-443\imaps tcp-993\pop3s tcp-995\smtps tcp-465)
DEFAULT_PORTS += ',2049'         #NFS linux网络共享服务
DEFAULT_PORTS += ',2082,2083'   # cpanel主机管理系统登陆 （国外用较多）​
DEFAULT_PORTS += ',2222'        # DA虚拟主机管理系统登陆 （国外用较多）​
DEFAULT_PORTS += ',2601,2604'   # zebra路由，默认密码zebra
DEFAULT_PORTS += ',3128'        # squid代理默认端口，如果没设置口令很可能就直接漫游内网了
DEFAULT_PORTS += ',3312,3311'   # kangle主机管理系统登陆
DEFAULT_PORTS += ',4440'        # rundeck  参考WooYun: 借用新浪某服务成功漫游新浪内网
DEFAULT_PORTS += ',5432,5631'
DEFAULT_PORTS += ',6082'        # varnish  参考WooYun: Varnish HTTP accelerator CLI 未授权访问易导致网站被直接篡改或者作为代理进入内网
DEFAULT_PORTS += ',6379'        # redis 一般无认证，可直接访问
DEFAULT_PORTS += ',7001'        # weblogic，默认弱口令
DEFAULT_PORTS += ',7778'        # Kloxo主机控制面板登录​
DEFAULT_PORTS += ',8000'        # 8000-9090都是一些常见的web端口，有些运维喜欢把管理后台开在这些非80的端口上
DEFAULT_PORTS += ',8001'
DEFAULT_PORTS += ',8002'
DEFAULT_PORTS += ',8080'        # tomcat/WDCP主机管理系统 默认端口
DEFAULT_PORTS += ',8081'
DEFAULT_PORTS += ',8888'        # amh/LuManager 主机管理系统默认端口
DEFAULT_PORTS += ',8083'        # Vestacp主机管理系统​​ （国外用较多）
DEFAULT_PORTS += ',8089'        # jboss端口 历史曾经爆漏洞/可弱口令
DEFAULT_PORTS += ',9200'        # elasticsearch port
DEFAULT_PORTS += ',10000'       # Virtualmin/Webmin 服务器虚拟主机管理系统
DEFAULT_PORTS += ',11211'       # memcache  未授权访问
DEFAULT_PORTS += ',14147'
DEFAULT_PORTS += ',28017,27017' # mongodb default port
DEFAULT_PORTS += ',43958'



logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")



class MyThread(threading.Thread):
    def __init__(self, func):
        super(MyThread, self).__init__()
        self.func = func
    def run(self):
        self.func()

class Pyscan(object):
    def __init__(self):
        self.SHARE_Q=Queue()
        self.info=Queue()
        self.tool=Tools()

    def socket_port(self,ip,port):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result=s.connect_ex((str(ip),int(port)))
            if result==0:
                return True
            s.close()
        except:
            return False


    def worker(self) :
        while not self.SHARE_Q.empty():
            try:
                ip,port = self.SHARE_Q.get()
                p=self.place
                if self.socket_port(ip,port):
                    self.info.put((ip,port))
                    sys.stdout.write('{0}{1}{2}{3}open\n'.format(ip,p(18-len(ip)),port,p(10-len(port))))
                    # sys.stdout.flush()
            except Exception as e:
                pass
            self.SHARE_Q.task_done()

    def place(self,n=10):
        return " "*n


    def reports(self):
        _info=[]
        with open(self.tool._file(".py.md"),"w") as f:
            while not self.info.empty():
                _info.append(self.info.get())
            info=self.par_rep(_info)
            for ip,ports in info.iteritems():
                place = " " * (18-len(ip))
                f.write('{0}{1}{2}\n'.format(ip,place,','.join(ports)))


    def par_rep(self,result):
        ip=[]
        target = {}
        for i in result:
            ip.append(i[0])
        for ip_ in set(ip):
            ports=[]
            for p in result:
                if ip_ == p[0]:
                    ports.append(p[1])
            target[ip_] = ports
        return target


    def par_queue(self,file=None,ip=None,ports=None):
        targets=[]
        for i in self.tool.par_ip(file,ip):
            for p in self.tool.par_ports(ports):
                targets.append((i,p))
        return targets


    def pyscan(self,file=None,ip=None,ports=None,ts=100):
        threads = []
        for info in self.par_queue(file,ip,ports):
            self.SHARE_Q.put(info)
        logging.info("Total have {} tasks , now starting.....".format(self.SHARE_Q.qsize()))
        for i in xrange(ts):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        for thread in threads :
            thread.join()
        self.SHARE_Q.join()
        self.reports()
        logging.info("FAST scan result in {}".format(self.tool._file(".py.md")))



class Tools(object):
    def __init__(self):
        self.p=re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')


    def _file(self,ext):
        path_=os.path.abspath(os.path.dirname(__file__))+os.sep
        name_=datetime.now().date().isoformat()+ext
        return path_+name_

    def cidr(self,net):
        _ip_list=[]
        ips=IPy.IP(net)
        for _ip in ips:
            _ip_list.append(str(_ip))
        ip_list=_ip_list[1:-1]
        return ip_list

    def par_ip(self,file_=None,ip=None):
        ips=[]
        if file_:
            ips= [x.strip() for x in file(file_,'rb')]
        elif "/" in ip: ips.extend(self.cidr(ip))
        elif '-' in ip: ips.extend(self.ipran(ip))
        elif self.p.match(ip): ips.append(ip)
        return set(ips)


    def ipran(self,iprange):
        ip_list_tmp = []
        iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
        numtoip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])
        if '-' in iprange:
            ip_range = iprange.split('-')
            ip_start = long(iptonum(ip_range[0]))
            ip_end = long(iptonum(ip_range[1]))
            ip_count = ip_end - ip_start
            if ip_count >= 0 and ip_count <= 655360:
                for ip_num in range(ip_start, ip_end + 1):
                    ip_list_tmp.append(numtoip(ip_num))
            else:
                print 'IP format error'
        else:
            ip_split = iprange.split('.')
            net = len(ip_split)
            if net == 2:
                for b in range(1, 255):
                    for c in range(1, 255):
                        ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                        ip_list_tmp.append(ip)
            elif net == 3:
                for c in range(1, 255):
                    ip = "%s.%s.%s.%d" % (ip_split[0], ip_split[1], ip_split[2], c)
                    ip_list_tmp.append(ip)
            elif net == 4:
                ip_list_tmp.append(iprange)
            else:
                print "IP format error"
        return ip_list_tmp


    def par_ports(self,ports=None):
        global DEFAULT_PORTS
        _port=[]
        if ports:
            for x in ports.split(','):
                if '-' in x:
                    _locs = x.split('-')
                    _ports = range(int(_locs[0]),int(_locs[1])+1)
                    _port.extend(_ports)
                else:
                    _port.append(int(x))
        else:
            _port=DEFAULT_PORTS.split(',')
        return set(_port)



class Nmapscan(object):
    def __init__(self):
        self.info=Queue()
        self.SHARE_Q=Queue()
        self.tool=Tools()


    def worker(self):
        while not self.SHARE_Q.empty():
            try:
                ip,port = self.SHARE_Q.get()
                scanner = nmap.PortScanner()
                scanner.scan(ip,ports=port,arguments='-Pn -sT -sV --allports --version-trace')
                for host in scanner.all_hosts():
                    _tcp = scanner[host]['tcp']
                    if scanner[host].state() == 'up' and _tcp:
                        for port in _tcp:
                            if _tcp[int(port)]['state'] == 'open':
                                p=self.place
                                name = _tcp[int(port)]['name']
                                product = _tcp[int(port)]['product']
                                version = _tcp[int(port)]['version']
                                sys.stdout.write("{}{}tcp{}{}{}{}{}{}{}{}\n".format(ip,p(18-len(ip)),p(),
                                port,p(7-len(str(port))),
                                name,p(25-len(name)),
                                product,p(35-len(product)),
                                version))
                                self.info.put((ip,"tcp",str(port),name,product,version))
            except Exception, e:
                pass
            self.SHARE_Q.task_done()


    def place(self,n=3):
        return " "*n


    def nmap(self,file=None,ip=None,ports=None,ts=10):
        threads = []
        for info in self.par_queue(file,ip,ports):
            self.SHARE_Q.put(info)
        logging.info("Total have {} tasks , now starting.....".format(self.SHARE_Q.qsize()))
        for i in xrange(ts):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        for thread in threads :
            thread.join()
        self.SHARE_Q.join()
        self.reports(self.info)
        logging.info("NMAP scan result in {}".format(self.tool._file(".port.csv")))


    def reports(self,info):
        with open(self.tool._file(".port.csv"), 'wb') as f:
            writer = csv.writer(f)
            writer.writerow(['IP','protocal','port','name','product','version'])
            while not self.info.empty():
                writer.writerow(self.info.get())


    def par_queue(self,file=None,ip=None,ports=None):
        targets=[]
        tool=Tools()
        for i in tool.par_ip(file,ip):
            if self.par_ports(ports):
                for p in self.par_ports(ports):
                    targets.append((i,p))
            else:
                targets.append((i,None))
        return targets



    def par_ports(self,ports=None):
        _port=[]
        if ports:
            for x in ports.split(','):
                if '-' in x:
                    _locs = x.split('-')
                    _ports = range(int(_locs[0]),int(_locs[1])+1)
                    _port.extend(_ports)
                else:
                    _port.append(int(x))
        return set([str(x) for x in _port])



class Masscan(object):

    def __init__(self):
        self.tool=Tools()
        self.path=os.path.abspath(os.path.dirname(__file__))+os.sep

    def masscan(self,file=None,ip='',ports="1-65535",ts=100):
        if file:
            filename =self.path+file
            logging.info("masscan -p{} {} -oL {} "
                      "--randomize-hosts --banners --rate={}".format(ports,'-iL'+' '+filename,
                        self.tool._file(".port.ms"),ts))
            os.system("masscan -p{} {} -oL {} "
                      "--randomize-hosts --banners --rate={}".format(ports,'-iL'+' '+filename,
                        self.tool._file(".port.ms"),ts))
        if ip:
            logging.info("masscan {} -p{} -oL {} "
                      "--randomize-hosts --banners --rate={}"
                      .format(ip,ports,self.tool._file(".port.ms"),ts))
            os.system("masscan {} -p{} -oL {} "
                      "--randomize-hosts --banners --rate={}"
                      .format(ip,ports,self.tool._file(".port.ms"),ts))
        logging.info("MASSCAN scan result in {}".format(self.tool._file(".port.ms")))


def cmdParser():
    parser = argparse.ArgumentParser(usage='python %s -i "192.168.1.0/24" -m nmap'%__file__)
    parser.add_argument('-f','--file',metavar="",help='ips filename')
    parser.add_argument('-i','--ips',metavar="",help='support CIDR | RANGE |SINGLE ips')
    parser.add_argument('-p','--ports',metavar="",help='support RANGE | SINGLE ports')
    parser.add_argument('-t','--threads',metavar="",default=100,type=int,help='THREADS')
    parser.add_argument('-m','--mode',metavar="",default="pyscan",help='Type [pyscan | nmap | masscan]')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args



if __name__ == "__main__":
    args=cmdParser()
    # print args.file,args.ips,args.ports,args.threads,args.mode
    if args.mode == "pyscan":
        Pyscan().pyscan(file=args.file,ip=args.ips,ports=args.ports,ts=args.threads)
    if args.mode == "nmap":
        Nmapscan().nmap(file=args.file,ip=args.ips,ports=args.ports,ts=args.threads)
    if args.mode == "masscan":
        Masscan().masscan(file=args.file,ip=args.ips,ports=args.ports,ts=args.threads)

