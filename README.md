# scantools

### 0x1 acunetix.py
- acunetix.py适用于一次性添加或删除大量AWVS扫描任务的情况，只支持avws11.

- 修改配置 <br>
首先修改脚本中的地址和api <br>
    aws = "https://192.168.55.144:3443/" #这里修改为awvs地址 <br>
    key = "1986ad8c0a5b3df4d7028d5f3c06e936cf472814bd5a2479485f28e11e0811afa" #修改为你的扫描器api-key <br>
  api-key需要手动生成，方法是登录awvs，右上角administrator --> profile  往下拉到底有API的选项复制出来 <br>
  
- 主要功能 <br>
  - 支持单url添加扫描任务，-u http://www.xx.com
  - 支持批量添加扫描任务,-f urls.txt 添加urls.txt中的所有连接到扫描任务
  - 支持指定扫描类型，全扫描、高危漏洞、仅爬取、跨站、SQL注入、快速扫描,-m 1
  - 支持自定义每个任务的扫描时间，避免单个任务耗时太久，默认单位是秒,-t 1000 
  - 支持批量删除任务，-d all 会删除当前所有任务，-d url.txt 会删除利用url.txt文件添加的所有任务
 
 - 基本用法 <br>
python acunetix.py -u http://www.xx.com -m 1 <br>
python acunetix.py -f urls.txt -m 2 <br>
python acunetix.py -f urls.txt -m 1 -t 1000 <br>
python acunetix.py -d all <br>
python acunetix.py -d urls.txt <br>

### 0x2 scanports.py
- scanports.py 适用于发现批量目标风险端口开放情况，默认使用了socket连接扫描，自定了一部分风险端口，如果不指定端口，会扫描默认的风险端口，扫描速度极快。脚本还支持调用nmap批量扫描，可以输出更为详细的服务信息，适用于指定端口的扫描，全端口扫描效率相对较低。<br>

 - 基本用法 <br>
python scanports.py -i 192.168.55.155/24 <br>
python scanports.py -i 192.168.55.155/24 -p 3306,1433,1521,5432,27017,6379<br>
python scanports.py -i 192.168.55.155/24 -f ips.txt<br>
python scanports.py -i 192.168.55.155/24 -p 80,8080 -m nmap <br>
