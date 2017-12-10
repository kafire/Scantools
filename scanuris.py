#coding: utf-8

import os
import re
import sys
import socket
import logging
import requests
import argparse
import threading
from Queue import Queue
from urlparse import urlparse


try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

reload(sys)
sys.setdefaultencoding('utf-8')


socket.setdefaulttimeout(10)


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")


class MyThread(threading.Thread):
    def __init__(self, func):
        super(MyThread, self).__init__()
        self.func = func
    def run(self):
        self.func()


class Scanuri(object):
    def __init__(self,status,keyword):
        self.targets=[]
        self.path=[]
        self.reports=[]
        self.keyword=keyword
        self.type="GET"
        self.SHARE_Q=Queue()
        self.status=status.split(',') if ',' in status else status
        self._path=os.path.abspath(os.path.dirname(__file__))+os.sep
        self.header = {"content-type": "application/json",
                       'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                       'Accept-Encoding': 'gzip, deflate, br',
                       'Content-Type': 'application/json;charset=utf-8',
                       'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'
                       }


    def get_urls(self,_file,_url):
        urls=[]
        if _url:
            urls.append(_url)
        elif _file:
            for i in [x.strip() for x in file(_file,'r')]:
                urls.append(i)
        return urls


    def get_path(self,_dict,_uri):
        if _uri:
            self.path.append(_uri)
        if _dict:
            for x in file(_dict,'r').readlines():
                self.path.append(x.strip())
        return len(self.path)


    def get_burls(self,url_):
        urls=[]
        urls_path=['']
        if not url_.find('://') > 0:
            url = 'http://' + url_
        else:
            url=url_
        obj=urlparse(url.strip())
        if obj.path != '':
            path_arr=obj.path.split('/')
            path_arr.pop()
            path_=''
            for i in path_arr:
                if i != '':
                    path_ = path_ + '/' + i
                    urls_path.append(path_)
        for _ in urls_path:
            urls.append('{}://{}{}'.format(obj.scheme,obj.netloc,_))
        return urls


    def get_targets(self,_file,_url):
        for url in self.get_urls(_file,_url):
            self.SHARE_Q.put(url)
        return self.SHARE_Q.qsize()


    def identify_waf(self,resp):
        if re.search('self\.location="(/\?WebShieldSessionVerify=[0-9a-zA-Z]+?)";', resp.content):
            return True
        return False

    def place(self,n=5):
        return " "*n

    def report(self):
        with open(self._path+'result.txt', 'wb') as f:
            for url,status,tag in self.reports:
                f.write(url+self.place()+str(status)+self.place()+self.keyword + '\n')
        return len(file('result.txt').readlines())


    def worker(self):
        while not self.SHARE_Q.empty():
            url=self.SHARE_Q.get()
            skip = False
            for url_ in self.get_burls(url):
                if skip:break
                for path_ in self.path:
                    url=url_.strip('/')+'/'+ path_
                    resp,status=self.request(url,self.type)
                    if status == -1:
                        skip= True
                        break
                    report=False
                    if self.status and self.keyword:
                        if str(status) in self.status:
                            if self.keyword and self.keyword in resp.content:
                                print url, self.keyword
                                report=True
                    else:
                        if str(status) in self.status:
                            if not self.identify_waf(resp):
                                print url,status
                                report=True
                        if self.keyword and self.keyword in resp.content:
                            print url,self.keyword
                            report=True
                    if report:
                        self.reports.append((url,status,self.keyword))
                        skip= True
                        break


    def request(self,url,type):
        resp=None
        s=requests.session()
        try:
            if type=="GET":
                resp=s.get(url,timeout=10, verify=False, headers=self.header,allow_redirects=False)
                status = resp.status_code
            if type == "POST":
                resp=s.post(url,timeout=10, verify=False, headers=self.header,allow_redirects=False)
                status=resp.status_code
            if re.search('<body onload="t3_ar_guard\(\);">', resp.content):
                print 't3_ar_guard',url
                match = re.search(
                    '\'document\|href\|location\|cookie\|([0-9a-zA-Z_]*?)\|path\|([0-9]*?)\|([0-9]*?)\'', resp.content)
                if match:
                    self.header['Cookie'] = ";%s=%s/%s" % (match.group(1), match.group(3), match.group(2))
                    _resp = requests.get(url=url, timeout=10, verify=False, headers=self.header, allow_redirects=False)
                    return _resp, _resp.status_code
        except Exception as e:
            try:
                if type == 'GET':
                    resp = s.get(url=url, timeout=10, verify=False, allow_redirects=False)
                    status = resp.status_code
                elif type == 'POST':
                    resp = s.post(url=url, timeout=10, verify=False, allow_redirects=False)
                    status = resp.status_code
            except Exception as e:
                status = -1
        return resp,status



    def urlscan(self,_threads=10):
        logging.info("Now start checking !!!" )
        threads=[]
        for i in xrange(_threads):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        records=self.report()
        logging.info("Total find %s records !!!"% records)


def cmdParser():
    parser = argparse.ArgumentParser(usage='python %s ' % __file__)
    parser.add_argument('-m','--method',metavar="",dest='method', default='GET', help='GET|POST')
    parser.add_argument('-s','--status',metavar="",dest='status', default=None, required=True, help='status code')
    parser.add_argument('-k','--keyword',metavar="",dest='keyword', default='', help='keyword in content')
    parser.add_argument('-p','--path',metavar="",dest='path', default=None, help='path')
    parser.add_argument('-t','--target',metavar="",dest='target', default=None, help='target')
    parser.add_argument('-f','--file',metavar="",dest='file', default=None, help='filename for targets')
    parser.add_argument('-d','--dict',metavar="",dest='dict', default=None, help='filename for paths')
    parser.add_argument('-n','--threads',metavar="",dest='threads', default=10, type=int, help='threads numbers,default 10 !')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args


if __name__ == '__main__':

    args=cmdParser()
    if not (args.file or args.target):
        print sys.exit('Typing -h for help')
    if not (args.path or args.dict):
        print sys.exit('Typing -h for help')
    scanuri = Scanuri(args.status, args.keyword)
    scanuri.get_targets(args.file,args.target)
    scanuri.get_path(args.dict, args.path)
    scanuri.urlscan(args.threads)
