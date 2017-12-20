#coding: utf-8

import re
import os
import csv
import sys
import nmap
import time
import socket
import logging
import argparse
import threading
from Queue import Queue

mutex = threading.Lock()

path = os.path.join(__file__,'log.txt')

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass


reload(sys)
sys.setdefaultencoding('utf-8')

socket.setdefaulttimeout(3)


DEFAULT_PORTS= '21,22,23,25,53,67,68,69,80-89'
DEFAULT_PORTS += ',110,135,139,143,161'
DEFAULT_PORTS += ',389'
DEFAULT_PORTS += ',443,465'
DEFAULT_PORTS += ',512,513,514'     #linux 直接使用rlogin
DEFAULT_PORTS += ',873'         # rsync default port  
DEFAULT_PORTS += ',993,995' # ssl services port(https tcp-443\imaps tcp-993\pop3s tcp-995\smtps tcp-465)
DEFAULT_PORTS += ',1080'       #socket 爆破：进行内网渗透
DEFAULT_PORTS += ',1352'       #lotus  爆破：弱口令  信息泄漏：源代码
DEFAULT_PORTS += ',1433'
DEFAULT_PORTS += ',1521,1526' 
DEFAULT_PORTS += ',2049'         #NFS linux网络共享服务
DEFAULT_PORTS += ',2181'        #zookeeper  未授权访问
DEFAULT_PORTS += ',2082,2083'   # cpanel主机管理系统登陆 （国外用较多）​
DEFAULT_PORTS += ',2222'        # DA虚拟主机管理系统登陆 （国外用较多）​
DEFAULT_PORTS += ',2601,2604'   # zebra路由，默认密码zebra
DEFAULT_PORTS += ',3128'        # squid代理默认端口，如果没设置口令很可能就直接漫游内网了
DEFAULT_PORTS += ',3312,3311,3306'   # kangle主机管理系统登陆
DEFAULT_PORTS += ',3389' 
DEFAULT_PORTS += ',4440'        # rundeck  参考WooYun: 借用新浪某服务成功漫游新浪内网
DEFAULT_PORTS += ',4848'        #glassfish 爆破：控制台弱口令 认证绕过,GlassFish 任意文件读取
DEFAULT_PORTS += ',4899' 
DEFAULT_PORTS += ',5000'        #sybase/DB2爆破、注入
DEFAULT_PORTS += ',5432,5631'   #postgresql 缓冲区溢出、注入攻击、爆破：弱口令 / pcanywhere、拒绝服务、代码执行
DEFAULT_PORTS += ',5900'        #vnc、爆破：弱口令、认证绕过
DEFAULT_PORTS += ',5984'        #CouchDB http://xxx:5984/_utils/
DEFAULT_PORTS += ',6082'        # varnish  参考WooYun: Varnish HTTP accelerator CLI 未授权访问易导致网站被直接篡改或者作为代理进入内网
DEFAULT_PORTS += ',6379'        # redis 一般无认证，可直接访问
DEFAULT_PORTS += ',7001,7002'        # weblogic，默认弱口令
DEFAULT_PORTS += ',7778'        # Kloxo主机控制面板登录​
DEFAULT_PORTS += ',8000-9090'        # 8000-9090都是一些常见的web端口，有些运维喜欢把管理后台开在这些非80的端口上
DEFAULT_PORTS += ',8001'
DEFAULT_PORTS += ',8002'
DEFAULT_PORTS += ',8069'        #zabbix  远程命令执行
DEFAULT_PORTS += ',8080'        # tomcat/WDCP主机管理系统 默认端口
DEFAULT_PORTS += ',8081,8580'
DEFAULT_PORTS += ',8888'        # amh/LuManager 主机管理系统默认端口
DEFAULT_PORTS += ',8083'        # Vestacp主机管理系统​​ （国外用较多）
DEFAULT_PORTS += ',8089'        # jboss端口 历史曾经爆漏洞/可弱口令
DEFAULT_PORTS += ',8161'        #ActiveMQ  admin:admin
DEFAULT_PORTS += ',8649'        #ganglia
DEFAULT_PORTS += ',9000'        # PHP-FPM Fastcgi 未授权访问漏洞
DEFAULT_PORTS += ',9090'        # websphere控制台、爆破：控制台弱口令、Java反序列
DEFAULT_PORTS += ',9200,9300'   # elasticsearch port ，命令执行
DEFAULT_PORTS += ',10000'       # Virtualmin/Webmin 服务器虚拟主机管理系统
DEFAULT_PORTS += ',11211'       # memcache  未授权访问
DEFAULT_PORTS += ',14147'
DEFAULT_PORTS += ',27018'
DEFAULT_PORTS += ',28017,27017'  # mongodb default port
DEFAULT_PORTS += ',43958'
DEFAULT_PORTS += ',50000'        #SAP命令执行
DEFAULT_PORTS += ',50070,50030'  #hadoop默认端口未授权访问


logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")


class Tools(object):
    def __init__(self):
        self.p=re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')


    def _file(self,prefix=None,suffix=None):
        path_=os.path.abspath(os.path.dirname(__file__))+os.sep
        if prefix:
            name_=prefix+time.strftime('%Y%m%d%H%M%S',time.localtime(time.time()))+".txt"
        if suffix:
            name_ =time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())) + suffix
        return path_+name_

    def stringxor(self,str1, str2):
        orxstr = ""
        for i in range(0, len(str1)):
            rst = int(str1[i]) & int(str2[i])
            orxstr = orxstr + str(rst)
        return orxstr

    def bin2dec(self,string_num):
        return str(int(string_num, 2))

    def getip(self,ip, type):
        result = ''
        for i in range(4):
            item = self.bin2dec(ip[0:8])
            if i == 3:
                if type == 0:
                    item = str(int(item) + 1)
                else:
                    item = str(int(item) - 1)
            result = result + item + '.'
            ip = ip[8:]
        return result.strip('.')


    def CIDR(self,input):
        try:
            ip = input.split('/')[0]
            pos = int(input.split('/')[1])
            ipstr = ''
            for i in ip.split('.'):
                ipstr = ipstr + bin(int(i)).replace('0b', '').zfill(8)
            pstr = '1' * pos + '0' * (32 - pos)
            res = self.stringxor(ipstr, pstr)
            _ip = self.getip(res, 0), self.getip(res[0:pos] + '1' * (32 - pos), 1)
            return _ip[0] + "-" + _ip[1]
        except:
            print 'cidr format error!!!'


    def par_ip(self,file_=None,ip=None):
        ips=[]
        if file_:
            ips= [x.strip() for x in file(file_,'rb')]
        elif "/" in ip: ips.extend(self.ipran(self.CIDR(ip)))
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
            for _ in DEFAULT_PORTS.split(','):
                if '-' in _:
                    _locs = _.split('-')
                    _ports = range(int(_locs[0]),int(_locs[1])+1)
                    _port.extend(_ports)
                else:
                    _port.append(int(_))
        return set(_port)


    def host2ip(self,host):
        try:
            ip =socket.gethostbyname(host)
            return (host,ip)
        except:
            mutex.acquire()
            print host+self.place(20)+': DNS requests fail'
            mutex.release()
            return (host, None)


    def place(self,n=10):
        return " "*n


class MyThread(threading.Thread):
    def __init__(self, func):
        super(MyThread, self).__init__()
        self.func = func
    def run(self):
        self.func()

class Pyscan(object):
    def __init__(self):
        self.SHARE_Q=Queue()
        self.info=[]
        self.tool=Tools()
        self.ports=[]


    def socket_port(self,ip,port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result=s.connect_ex((str(ip),int(port)))
            if result==0:
                return True
        except:
            return False
        finally:
            s.close()


    def worker(self) :
        while True:
            try:
                _host = self.SHARE_Q.get(block=False)
            except:
                break
            try:
                host,ip= self.tool.host2ip(_host)
                p=self.place
                for port in self.ports:
                    if self.socket_port(ip,port):
                        self.info.append((ip,str(port)))
                        mutex.acquire()
                        sys.stdout.write('{0}{1}{2}\n'.format(ip,p(25-len(ip)),port))
                        mutex.release()
            except Exception as e:
                print e


    def place(self,n=10):
        return " "*n


    def reports(self):
        with open(self.tool._file(prefix='ports_'),"w") as f:
            info=self.par_rep(self.info)
            for ip,ports in info.iteritems():
                place = " " * (30-len(ip))
                f.write('{0}{1}{2}\n'.format(ip,place,','.join(ports)))


    def hydra(self):
        with open(self.tool._file(prefix="hydra_"),"w") as f:
            for domin,port in self.info:
                host,ip=Tools().host2ip(domin)
                if port=="21":
                    f.write("ftp://%s:%d\n"%(ip,int(port)))
                elif port=="22":
                    f.write("ssh://%s:%d\n" % (ip,int(port)))
                elif port=="3306":
                    f.write("mysql://%s:%d\n" % (ip,int(port)))
                elif port=="1433":
                    f.write("mssql://%s:%d\n" % (ip,int(port)))
                if port=="110":
                    f.write("pop3://%s:%d\n"%(ip,int(port)))


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


    def monitor(self):
        while not self.SHARE_Q.empty():
            logging.info("current has {} tasks waiting...".format(self.SHARE_Q.qsize()))
            time.sleep(30)


    def pyscan(self,file=None,ip=None,ports=None,hydra=False,ts=10):
        threads = []
        self.ports = self.tool.par_ports(ports)
        for info in self.tool.par_ip(file,ip):
            self.SHARE_Q.put(info)
        logging.info("Total have {} tasks , now starting.....".format(self.SHARE_Q.qsize()))
        for i in xrange(ts):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        self.monitor()
        for thread in threads :
            thread.join()
        if hydra:
            self.hydra()
            logging.info("Hydra scan result in {}".format(self.tool._file(prefix="hydra_")))
        self.reports()
        logging.info("Fast scan result in {}".format(self.tool._file(prefix='ports_')))




class Nmapscan(object):
    def __init__(self):
        self.info=[]
        self.SHARE_Q=Queue()
        self.tool=Tools()


    def worker(self):
        while True:
            try:
                _host, port = self.SHARE_Q.get(block=False)
            except:
                break
            try:
                host,ip=self.tool.host2ip(_host)
                if ip:
                    scanner = nmap.PortScanner()
                    scanner.scan(ip,ports=port,arguments='-Pn -sT -sV --allports --version-trace')
                    # print scanner.command_line()
                    for host in scanner.all_hosts():
                        _tcp = scanner[host]['tcp']
                        if scanner[host].state() == 'up' and _tcp:
                            for port in _tcp:
                                if _tcp[int(port)]['state'] == 'open':
                                    p=self.place
                                    name = _tcp[int(port)]['name']
                                    product = _tcp[int(port)]['product']
                                    version = _tcp[int(port)]['version']
                                    mutex.acquire()
                                    print host, "tcp_", str(port), name, product, version
                                    mutex.release()
                                    self.info.append((host,"tcp",str(port),name,product,version))
            except Exception, e:
                print e


    def place(self,n=5):
        return " "*n

    def monitor(self):
        while not self.SHARE_Q.empty():
            logging.info("current has {} tasks waiting...".format(threading.activeCount() - 1))
            time.sleep(120)


    def nmap(self,file=None,ip=None,ports=None,ts=10):
        threads = []
        for info in self.par_targets(file,ip,ports):
            self.SHARE_Q.put(info)
        logging.info("Total have {} tasks , now starting.....".format(self.SHARE_Q.qsize()))
        for i in xrange(ts):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        self.monitor()
        for thread in threads :
            thread.join()
        self.reports()
        logging.info("NMAP scan result in {}".format(self.tool._file(suffix=".csv")))


    def reports(self):
        with open(self.tool._file(suffix=".csv"), 'wb') as f:
            writer = csv.writer(f)
            writer.writerow(['IP','protocal','port','name','product','version'])
            for _info in self.info:
                writer.writerow(_info)


    def par_targets(self,file=None,ip=None,ports=None):
        targets=[]
        tool=Tools()
        for i in tool.par_ip(file,ip):
            targets.append((i, ports))
        return targets


def cmdParser():
    parser = argparse.ArgumentParser(usage='python %s -i "192.168.1.0/24" -m nmap'%__file__)
    parser.add_argument('-f','--file',metavar="",help='Ips filename')
    parser.add_argument('-i','--ips',metavar="",help='Support cidr | range |singe ips')
    parser.add_argument('-p','--ports',metavar="",help='Support range | single ports')
    parser.add_argument('-c','--hydra',action="store_true",default=False,help='Format For Hydra')
    parser.add_argument('-t','--threads',metavar="",default=20,type=int,help='Threads numbers,default 20')
    parser.add_argument('-m','--mode',metavar="",default="pyscan",help='Type [pyscan | nmap | masscan]')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args=cmdParser()
    if not (args.file or args.ips):
        print sys.exit('-h for help')
    if args.mode == "pyscan":
        Pyscan().pyscan(file=args.file,ip=args.ips,ports=args.ports,hydra=args.hydra,ts=args.threads)
    if args.mode == "nmap":
        Nmapscan().nmap(file=args.file,ip=args.ips,ports=args.ports,ts=args.threads)

