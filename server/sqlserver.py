# -*- codeing = uef-8 -*-
# @Time:2021/9/6 20:03
# @Author:刘双鱼
# @File:sqlserver.py
# @Software:PyCharm
import pymysql
import os
#函数列表：
#登录数据库：conn()
#建表的操作：maketable(ID)
#验证ID是否重复：find_id(ID)
#注册账号（ID不重复）：register(ID,PASSWORD,MAIL)
#创建组：creategroup(ID,GIDh,GCODE,GNAME,GID)
#登录账号：login(ID,PASSWORD)
#加入组：entergroup(ID,GIDh,GCODE,GID)
#退出组：exitgroup(ID,GIDh)
#获取文件列表(个人)：fileaccess(ID)
#获取加入组列表：getgrouplist(ID)
#获取文件列表(组)：fileaccess_t(GIDh)
#获取邮箱：mailaccess(ID)
#修改密码：passchange(ID,NEWPASSWORD)
#上传文件：uploadfile(ID,FILENAME,FILEROUTE,FILEPASS,0)
#获取文件：downloadfile(ID,FILEID)
#删除文件：deletefile(ID,FILEID)
#上传文件（组）：g_uploadfile(GIDh,FILENAME,FILEROUTE,FILEPASS,i)
#获取文件（组）：g_downloadfile(GIDh,FILEID)
#删除文件（组）：g_deletefile(GIDh,FILEID)

#登录操作
def conn():
    host = '10.122.199.84'#10.122.199.84
    port = 3306
    user = 'Administrator'
    passwd = '11235813'
    db = 'netdisk'
    charset = 'utf8mb4'
    sch=pymysql.connect(host=host,port=port,user=user,passwd=passwd,
                        db=db,charset=charset)
    if sch:
        return sch
    else:
        print('server connect error')
        os.system("pause")

#建表的操作
def maketable(ID):
    db = conn()
    cursor = db.cursor()
    sql = """create table %s(
                fileid int unsigned not null auto_increment,
                filename varchar(300) not null,
                fileroute varchar(300) not null,
                filepass varchar(300) not null,
                primary key (fileid))""" % ID
    cursor.execute(sql)
    db.commit()
    db.close()

#验证ID是否重复
def find_id(ID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT * FROM user where ID=%s"
    cursor.execute(sql,ID)
    #找到账号（搜索有结果）返回1，没有返回0
    if cursor.rowcount:
        db.close()
        return 1
    else:
        db.close()
        return 0

#注册账号（ID不重复）
def register(ID,PASSWORD,MAIL):
    db = conn()
    cursor=db.cursor()
    #账号ID不重复返回0，重复返回1
    if find_id(ID)==0:
        sql="INSERT INTO user VALUES (%s,%s,%s)"
        cursor.execute(sql,(ID,PASSWORD,MAIL))
        db.commit()
        maketable(ID)
        db.close()
        return 0
    else:
        db.close()
        return 1

#创建组
def creategroup(ID,GIDh,GCODE,GNAME,GID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT * FROM grouptable WHERE groupID=%s"
    cursor.execute(sql,GIDh)
    if cursor.rowcount:
        db.close()
        return 1
    else:
        sql="INSERT INTO grouptable VALUES (%s,%s,%s)"
        cursor.execute(sql,(GIDh,GCODE,GNAME))
        db.commit()
        sql="INSERT INTO usergroup VALUES (%s,%s,%s,%s)"
        cursor.execute(sql,(ID,GID,GNAME,GIDh))
        db.commit()
        maketable('g'+GIDh)
        db.close()
        return 0

#登录账号
def login(ID,PASSWORD):
    db = conn()
    cursor = db.cursor()
    if find_id(ID)==1:
        sql="SELECT ID FROM user WHERE ID=%s AND password=%s"
        cursor.execute(sql,(ID,PASSWORD))
        #登陆成功返回0，失败1
        if cursor.rowcount:
            db.close()
            return 0
        else:
            db.close()
            return 1
    else:
        #无账号返回2
        db.close()
        return 2

#加入组
def entergroup(ID,GIDh,GCODE,GID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT grouplist FROM usergroup WHERE userid=%s and grouphash=%s"
    cursor.execute(sql,(ID,GIDh))
    if cursor.rowcount:
        return 3
    sql = "SELECT groupID,groupcode,groupname FROM grouptable WHERE groupID=%s"
    cursor.execute(sql, GIDh)
    if cursor.rowcount:
        ginfo=cursor.fetchone()
        #加入成功返回0
        if ginfo[1]==GCODE:
            sql = "INSERT INTO usergroup VALUES (%s,%s,%s,%s)"
            cursor.execute(sql,(ID,GID,ginfo[2],ginfo[0]))
            db.commit()
            db.close()
            return 0
        #加入码错误返回1
        else:
            db.close()
            return 1
    #组ID不存在返回2
    else:
        db.close()
        return 2

#退出组
def exitgroup(ID,GIDh):
    db = conn()
    cursor = db.cursor()
    sql="DELETE FROM usergroup WHERE userid=%s and grouphash=%s"
    cursor.execute(sql,(ID,GIDh))
    db.commit()
    db.close()

#获取文件列表(个人)
def fileaccess(ID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT fileid,filename,filepass FROM %s"%ID
    cursor.execute(sql)
    fdict={}
    for i in range(cursor.rowcount):
        finfo=cursor.fetchone()
        #返回文件名，密钥，修改日期
        fdict[finfo[0]]=[finfo[1],finfo[2]]
    db.close()
    return fdict

#获取加入组列表
def getgrouplist(ID):
    db = conn()
    cursor = db.cursor()
    sql = "SELECT grouplist,groupname,grouphash FROM usergroup where userid='%s'" % ID
    cursor.execute(sql)
    fetchgroup=cursor.fetchall()
    gdict={}
    for i in range(cursor.rowcount):
        gdict[fetchgroup[i][2]]=[fetchgroup[i][1],fetchgroup[i][0]]
    db.close()
    return gdict

#获取文件列表(组)
def g_fileaccess(GIDh):
    return fileaccess('g'+GIDh)

#获取邮箱
def mailaccess(ID):
    db = conn()
    cursor = db.cursor()
    #有账号则返回邮箱，无则返回1
    sql = "SELECT email FROM user WHERE ID=%s"
    cursor.execute(sql,ID)
    if cursor.rowcount:
        mail=cursor.fetchone()[0]
        db.close()
        return mail
    else:
        db.close()
        return 1

#修改密码
def passchange(ID,NEWPASSWORD):
    db = conn()
    cursor = db.cursor()
    sql="UPDATE user SET password=%s WHERE ID=%s"
    cursor.execute(sql,(NEWPASSWORD,ID))
    db.commit()
    db.close()

#上传文件
def uploadfile(ID,FILENAME,FILEROUTE,FILEPASS,i):
    db = conn()
    cursor = db.cursor()
    sql="SELECT filename FROM %s WHERE filename='%s'"%(ID,FILENAME)
    cursor.execute(sql)
    #收到上传请求时检查文件名重复情况
    if cursor.rowcount:
        if i==0:
            #文件名重复时，为文件路径中的文件名加上后缀，返回文件路径
            name=FILENAME.split('.',1)
            fname=name[0]+'('+str(i+1)+')'+'.'+name[1]
            return uploadfile(ID,fname,FILEROUTE,FILEPASS,i+1)
        else:
            name=FILENAME.split('.',1)
            fname=name[0][0:len(name[0])-3]+'('+str(i+1)+')'+'.'+name[1]
            return uploadfile(ID,fname,FILEROUTE,FILEPASS,i+1)
    else:
        #文件名不重复时，直接保存文件名到路径中，返回路径
        fname=FILENAME
        froute=FILEROUTE+'/'+fname
        sql = "INSERT INTO %s (filename,fileroute,filepass)VALUES ('%s','%s','%s')"%(ID,fname,froute,FILEPASS)
        cursor.execute(sql)
        db.commit()
        db.close()
        return froute

#获取文件
def downloadfile(ID,FILEID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT fileroute FROM %s WHERE fileid='%s'"%(ID,FILEID)
    cursor.execute(sql)
    froute=cursor.fetchone()[0]
    db.close()
    return froute

#删除文件
def deletefile(ID,FILEID):
    db = conn()
    cursor = db.cursor()
    sql="SELECT fileroute FROM %s WHERE fileid='%s'"%(ID,FILEID)
    cursor.execute(sql)
    froute=cursor.fetchone()[0]
    sql="DELETE FROM %s WHERE fileid='%s'"%(ID,FILEID)
    cursor.execute(sql)
    db.commit()
    db.close()
    return froute

#上传文件（组）
def g_uploadfile(GIDh,FILENAME,FILEROUTE,FILEPASS,i):
    return uploadfile('g'+GIDh,FILENAME,FILEROUTE,FILEPASS,i)
#获取文件（组）
def g_downloadfile(GIDh,FILEID):
    return downloadfile('g'+GIDh,FILEID)
#删除文件（组）
def g_deletefile(GIDh,FILEID):
    return deletefile('g'+GIDh,FILEID)