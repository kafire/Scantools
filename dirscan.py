#coding: utf-8

import os
import sys
import time
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


class DirScan(object):
    def __init__(self):

        self.dirs=[]
        self.urls=[]
        self.prefix = ''
        self.suffix = ''
        self.targets=[]
        self.SHARE_Q=Queue()
        self.lock=threading.Lock()


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


    def get_urls(self,_file=None,_url=None):
        if _url:
            self.urls.append(_url)
        elif _file:
            for i in [x.strip() for x in file(_file,'r')]:
                self.urls.append(i)
        return len(self.urls)


    def get_dirs(self,_file=None,_dir=None):
        if _dir:
            self.dirs.append(self.prefix+_dir+self.suffix)
        if _file:
            for x in file(_file,'r').readlines():
                self.dirs.append(self.prefix+x.strip()+self.suffix)
        return len(self.dirs)


    def worker(self):
        while not self.SHARE_Q.empty():
            url_=self.SHARE_Q.get()
            for dir in self.dirs:
                url=url_.strip('/')+'/'+dir
                code,location=self.req_code(url)
                if code in [301,302]:
                    if location.endswith(dir+'/'):
                        self.targets.append(location)
            self.SHARE_Q.task_done()


    def scandir(self,_file=None,_url=None,report='targets.dir',ts=100):
        self.get_urls(_file,_url)
        for url_ in self.urls:
            if not url_:continue
            burls=self.get_burls(url_)
            for url in burls:
                self.SHARE_Q.put(url)
        logging.info("Total have {} tasks , now starting.....".format(self.SHARE_Q.qsize()))
        threads=[]
        for i in xrange(ts):
            thread = MyThread(self.worker)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        self.SHARE_Q.join()
        records=self.reports(report)
        logging.info("Total find %s records,reports in %s"
                     %(records,os.path.dirname(__file__)+os.sep+report))


    def req_code(self,url):
        _loc=None
        try:
            _resp = requests.get(url=url, timeout=10, verify=False, allow_redirects=False)
            _status = _resp.status_code
            _loc=_resp.headers['location']
        except Exception as e:
            try:
                _resp = requests.get(url=url, timeout=10, verify=False, allow_redirects=False)
                _status = _resp.status_code
                _loc=_resp.headers['location']
            except Exception as e:
                _status = -1
        return _status,_loc


    def reports(self,filename):
        with open(filename,"w") as f:
            for url in self.targets:
                f.write(url+'\n')
        return len(file(filename).readlines())


    # def count(self):
    #     while not self.SHARE_Q.empty():
    #         print 'Only %s tasks waiting to check...'% self.SHARE_Q.qsize()
    #         time.sleep(3)


def cmdParser():
    parser = argparse.ArgumentParser(usage='python %s -f "urls.txt" -d "phpMyAdmin"'%__file__)
    parser.add_argument('-f','--file',metavar="",help='urls filename')
    parser.add_argument('-u','--url',metavar="",help='url like "http://www.baidu.com/"')
    parser.add_argument('-l','--list',metavar="",help='dirs filename')
    parser.add_argument('-o','--outfile',metavar="",default='report.dir',help='report filename')
    parser.add_argument('-p','--prefix',metavar="",default='',help='add prefix')
    parser.add_argument('-s','--suffix',metavar="",default='',help='add suffix')
    parser.add_argument('-t','--threads',metavar="",default=100,type=int,help='THREADS')
    parser.add_argument('-d','--dir',metavar="",help='dir like "phpMyAdmin"')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = cmdParser()
    d=DirScan()
    d.prefix = args.prefix
    d.suffix = args.suffix
    i= d.get_dirs(_file=args.list,_dir=args.dir)
    if i==0:sys.exit("You must defind the scan dirs, use [-d,-l] help type -h")
    if args.file or args.url:
        d.scandir(_file=args.file,_url=args.url,report=args.outfile,ts=args.threads)
