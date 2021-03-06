#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import ssl
import json
import time
import urllib3
import argparse
import datetime
import requests
from Queue import Queue
import requests.packages.urllib3
from urlparse import urlparse
from argparse import RawTextHelpFormatter

# SSL error ignored
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings()

urls=[]
con_err=[]
par_err=[]


class Awvs(object):

    def __init__(self,url,apikey):
        self.url = url
        self.q=Queue()
        self.stats = url+"api/v1/me/stats"
        self.targets = url+"api/v1/targets"
        self.scans =url+"/api/v1/scans"
        self.path = os.path.abspath(os.path.dirname(__file__))+os.sep
        self.header = {"X-Auth":apikey,
                       "content-type": "application/json",
                       'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                       'Accept-Encoding': 'gzip, deflate, br',
                       'Content-Type': 'application/json;charset=utf-8',
                       'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'
                       }
        self.count()



    def request(self,_url,_method='POST',data=''):
        if _method=="POST":
            try:
                response = requests.post(_url,data=json.dumps(data),headers=self.header,timeout=30,verify=False)
                return response.ok,json.loads(response.content)
            except Exception as e:
                print(str(e))
                return
        elif _method == 'GET':
            try:
                response = requests.get(_url,headers=self.header,timeout=30,verify=False)
                return response.ok,json.loads(response.content)
            except Exception as e:
                print e
                # print "connect  failed ,please check AVWS URL and api api-key !"
                return



    def count(self):
        ok,req=self.request(self.stats,_method="GET")
        if ok:
            waiting = req.get("scans_waiting_count",'error')
            running = req.get("scans_running_count",'error')
            targets = req.get("targets_count","error")
            print "Total : %s ,Runing : %s ,Waiting : %s" % (targets,running,waiting)
            return running
        else:
            print "login fail,please check the api-key...."


    def add_task(self,url=None,mode=1):
        try:
            if "://"in url:
                date_ = time.strftime("%Y-%m-%d", time.localtime())
                data_= {"address":url,"description":date_,"criticality":"10"}
            else:
                par_err.append(url)
            ok_,req_= self.request(_url=self.targets,data=data_)
            if ok_:
                id = req_.get('target_id','')
                data = {"target_id":id,"profile_id":"11111111-1111-1111-1111-11111111111%s"% mode,
                         "schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
                ok,req= self.request(_url=self.scans,data=data)
                if ok:
                    print "[ INFO ] Success add target: %s"%  url.strip('\n')
            else:
                print '[ ERROR ] Add tasks url faild,please fomart url'
            self.is_err()
        except BaseException as e:
            print "[ ERROR ] Add task url error:\n%s"% e


    def is_err(self):
        global con_err
        global par_err
        if con_err:
            with open(self.path+'contect.err', 'w') as f:
                for x in con_err:f.write(x)
            print "="*50+"\n[ WARING ] %s records in %s"% (len(con_err),self.path)+'contect.err\n'+"="*50
        if par_err:
            with open(self.path+'parse.err', 'w') as f:
                for x in par_err:f.write(x)
            print "="*50+"\n[ WARING ]%s records in %s"% (len(par_err),self.path)+'parse.err\n'+"="*50



    def parse_url(self,url):
        _ = urlparse(url, 'http')
        if not _.netloc:
            return 'http://' + url
        else:
            return url



    def get_urls(self,file):
        global urls
        global par_err
        with open(self.path+file,'rb') as f:
            for i in f.readlines():
                link=self.parse_url(i)
                if "://" in link:
                    urls.append(link)
                else:
                    print "You must parse url like 'http://example.com'"
                    par_err.append(i)
        return urls


    def add_tasks(self,_file,mode=1):
        try:
            for i in self.get_urls(_file):
                url=i.strip()
                data_= {"address":url,"description":_file,"criticality":"10"}
                ok_,req_= self.request(_url=self.targets,data=data_)
                if ok_:
                    id = req_.get('target_id','')
                    data = {"target_id":id,"profile_id":"11111111-1111-1111-1111-11111111111%s"% mode,
                             "schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
                    ok,req= self.request(_url=self.scans,data=data)
                    if ok:
                        print "[ INFO ] Success add target: %s"%  url
                else:
                    print "[ ERROR ] Add tasks url faild,please fomart targets file"
            self.is_err()
        except BaseException as e:
            print "[ ERROR ] Add tasks file error:\n%s"% e



    def delete_scan(self,desc):
        while True:
            ok,req=self.request(self.targets,_method="GET")
            info_task = req.get("targets")
            if not info_task:break
            try:
                for info in req.get("targets"):
                    if desc=="all":
                        # print self.targets+"/"+info["target_id"]
                        req=requests.delete(self.targets+"/"+info["target_id"],headers=self.header,verify=False)
                        if req.ok:
                            print "success del target %s"% info["address"]
                    elif info["description"]== desc:
                        req=requests.delete(self.targets+"/"+info["target_id"],headers=self.header,verify=False)
                        if req.ok:
                            print "success del target %s"% info["address"]
            except BaseException as e:
                print "[ ERROR ] Delte task error:\n%s"% e



    def is_timeout(self,utc_time = None,timeout=None):
        try:
            parse = time.strptime(utc_time, "%Y-%m-%dT%H:%M:%S.%f+08:00")
            stamp=time.mktime(parse)
            struct= datetime.datetime.fromtimestamp(stamp)
            status= True if(datetime.datetime.now() -struct).seconds >timeout else False
            return status
        except BaseException as e:
            print "[ ERROR ] Parse time error:\n%s"% e


    def stop_scan(self,timeout=600):
        while True:
            try:
                url = self.scans+"?q=status:processing,aborting"
                ok,req = self.request(url,_method="GET")
                for info in req.get("scans"):
                    if self.is_timeout(info["current_session"]["start_date"],timeout=timeout):
                        stop_url=self.url+"api/v1/scans/"+info['scan_id']+"/abort"
                        req=requests.post(stop_url,headers=self.header,verify=False)
                        if req.ok:
                            print "[ INFO ] Aborting task %s"%(info["target"]["address"])
            except BaseException as e:
                print "[ ERROR ] Stop task error:\n%s"% e
            time.sleep(60)
            if self.count()==0:break


def cmdLineParser():
    parser = argparse.ArgumentParser(usage='python %s -f "urls.txt" -m 2'%__file__,formatter_class=RawTextHelpFormatter)
    parser.add_argument('-f','--file',metavar="",help='Load HTTP urls from a file')
    parser.add_argument('-d','--delete',metavar="",default=None,help='Delete tasks (e.g. "-d all" or "-d urls.txt")')
    parser.add_argument('-u','--url',metavar="",type=str,help='Target URL (e.g. "http://www.site.com/vuln.php?id=1")')
    parser.add_argument('-t','--timeout',metavar="",type=int,help='Stop timeout tasks (default Seconds)')
    parser.add_argument('-m','--mode',metavar="",default=1,type=int,
                        help='mode=1 (Full Scan (Default))\n'
                             'mode=2 (High Risk Vulnerabilities)\n'
                             'mode=3 (SQL Injection Vulnerabilities)\n'
                             'mode=7 (Crawl Only)\n'
                             'mode=6 (Cross-site Scripting Vulnerabilities)\n'
                             'mode=5 (Weak Passwords)\n'
                             'mode=8 (quick_profile continuous_quick)\n'
                             'mode=4 (quick_profile continuous_full)')
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args



if __name__ == '__main__':
    aws = "https://192.168.55.144:3443/"
    key = "1986ad8c0a5b3df4d7028d5f3c06e936cf472814bd5a2479485f28e11e0811afa"
    aws=Awvs(url=aws,apikey=key)
    args=cmdLineParser()
    # print args.file,args.mode,args.url,args.delete,args.timeout
    if args.file:
        aws.add_tasks(_file=args.file,mode=args.mode)
    if args.url:
        aws.add_task(url=args.url,mode=args.mode)
    if args.delete:
        aws.delete_scan(desc=args.delete)
    if args.timeout:
        aws.stop_scan(args.timeout)
