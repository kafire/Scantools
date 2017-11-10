# scantools

#### 0x1 acunetix.py
- acunetix.py适用于一次性添加或删除大量AWVS扫描任务的情况，只支持avws11

- 修改配置
首先修改脚本中的
    aws = "https://192.168.55.144:3443/" #这里修改为awvs地址
    key = "1986ad8c0a5b3df4d7028d5f3c06e936cf472814bd5a2479485f28e11e0811afa" #修改为你的扫描器api-key
    
  api-key需要手动生成，方法是登录awvs，右上角administrator --> profile  往下拉到底有API的选项复制出来
  
- 主要功能
  - 支持单url添加扫描任务，-u http://www.xx.com
  - 支持批量添加扫描任务,-f urls.txt 添加urls.txt中的所有连接到扫描任务
  - 支持指定扫描类型，全扫描、高危漏洞、仅爬取、跨站、SQL注入、快速扫描,-m 1
  - 支持自定义每个任务的扫描时间，避免单个任务耗时太久，默认单位是秒,-t 1000 
  - 支持批量删除任务，-d all 会删除当前所有任务，-d url.txt 会删除利用url.txt文件添加的所有任务
 
 - 基本用法
python acunetix.py -u http://www.xx.com -m 1 <br>
python acunetix.py -f urls.txt -m 2 <br>
python acunetix.py -f urls.txt -m 1 -t 1000 <br>
python acunetix.py -d all <br>
python acunetix.py -d urls.txt <br>
