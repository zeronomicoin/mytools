#!/usr/bin/env python
# coding: utf-8

import os,socket,sys,re,time,errno
from datetime import datetime

def showmytools():
    print('    """find(path,filename)"""\n\
    """grep(regex,file)"""\n\
    """cgrep(regex,file)"""\n\
    """uniq(file)"""\n\
    """myIPv4()"""\n\
    """ipinfo()"""\n\
    """infoservice(domain|host|IP,port)"""\n\
    """spingport(domain|host|IP,port)"""\n\
    """pingport(domain|host|IP,port)"""\n\
    """rotateby(key,txt,back=None)"""\n\
    """enterpassword(user)"""\n\
    """hex2bin(x)"""\n\
    """hex2dec(x)"""\n\
    """funnycrypt(dico,h)"""\n\
    """brutezip(zfile,dico)"""\n\
    """reverselookup(ip|domain)"""\n\
    """dnsrequest(domain)"""\n\
    """quadArecord(domain)"""\n\
    """hashme(algo,str(me))"""\n\
    """hashfile(algo,file)"""\n\
    """findandhash(path,filename,algo)"""\n\
    """shathat(dico,h)"""\n\
    """deltadirectory(src_dir,dst_dir) (abs. path)"""\n\
    """sshcmd(user,ip,[port])"""\n\
    """scanports(ip,*ports)"""\n\
    """exploresqlitedb(db_file (abs. path)"""\n\
    """epoch2date(unixtime)"""\n\
    """utc_epoch()"""\n\
    """epoch()"""')


def epoch():
    return datetime.now().strftime('%s')


def utc_epoch():
    return datetime.utcnow().strftime('%s')


def epoch2date(e):
    from datetime import datetime
    print(datetime.fromtimestamp(e).strftime('%c'))


def find(path,name):
    """find(path,file*name)"""
#    for r,d,f in os.walk(os.path.expanduser(path)):
#        if name in f:
#            print(os.path.join(r,name))
    from fnmatch import fnmatch
    res=[]
    for r,d,f in os.walk(os.path.expanduser(path)):
        for i in f:
                if fnmatch(i,name):
                    res.append(os.path.join(r,i))
    for j in res:
        print(j)
		


def grep(reg,fic):
    """grep(regex,file)"""
    with open(fic,'r') as f:
        for i in f.readlines():
            v=re.search(reg,i)
            if v: print(i)


def cgrep(reg,fic):
    """cgrep(regex,file)
    grep -c ..."""
    r=re.compile(reg)
    ls=[]
    with open(fic,'r') as f:
        for i in f.readlines():
            v=re.findall(r,i)
            if v:
                ls.append(v)
        print('%d %s'%(len(ls),reg))    


def uniq(fic):
    ls=[]
    new=fic+".uniq"
    with open(fic,'r') as f:
        for i in f.readlines():
            if i not in ls:
                ls.append(i)
    with open(new,"w") as out_f:
        for i in ls:
            out_f.write(i)
	print('%s created.'%new)


def infoservice(ip,port):
    socket.setdefaulttimeout(5)
    try:
        s=socket.socket()
        s.connect((ip,int(port)))
        s.sendall('GET / HTTP/1.0\r\n\r\n')
        print("%s:%d"%(ip,port))
        try:
            tmp=s.recv(1024)
            print(tmp)
        except:
            pass
    except Exception as e:
        print("%s:%d %s"%(ip,port,e))
        pass   
    s.close()


def spingport(x,y):
    """spingport(domain|host|IP,port)"""
    socket.setdefaulttimeout(3)
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((x,y))
        print('%s %s'%(x,socket.gethostbyname(x)))
    except socket.error as e:
        print('%s:%d  %s'%(x,y,e))
    finally:
        s.close()


def pingport(x,y):
    """pingport(domain|host|IP,port)"""
    socket.setdefaulttimeout(3)
    try:
        s=socket.socket()
        s.connect((x,int(y)))
        try:
          print('Protocol %s'%socket.getservbyport(int(y)))
          print('%s %s'%(x,int(y)))
        except Exception as e:
          print('%s %s'%(x,e))
        ls=[]
        for i in socket.getaddrinfo(x,int(y)):
            ip=i[-1][0]
            if ip not in ls:
                ls.append(ip)
        for j in ls:
            print('\t%s'%j)
        try:
            print(s.recv(2048))
        except:
            print('%s:%s Connection accepted'%(socket.gethostbyname(x),y))
    except Exception as e:
        print('%s:%s %s'%(x,y,e))
    finally:
        s.close()


def myIPv4(url='http://ping.eu'):
    import urllib2,re
    r=urllib2.Request(url)
    p=urllib2.urlopen(r)
    reg=re.compile('\d+\.\d+\.\d+\.\d+')
    ip=reg.findall(p.read())
    print('IP is %s'%ip[0])
    p.close()


def ipinfo(url='http://ipinfo.io'):
    from requests import get
    r=get(url).json()
    for i in r:
        print('%-10s%s'%(i,r[i]))


def rotateby(key,txt,back=None):
    """rotateby(key,txt,back=None)"""
    import string
    aZ=string.ascii_lowercase
    if back:
        key=26-key
    else:
        while key > 26:
            print('26 letters ...')
            key=input('Rotate by : ')
    r=aZ[key:]+aZ[0:key]
    tr=string.maketrans(aZ,r)
    return txt.lower().translate(tr)


def enterpassword(user):
    """enterpassword(user)"""
    from os import system as sh
    from base64 import encodestring
    from Crypto.Cipher import AES
    from hashlib import sha256
    if sys.platform.startswith('win'):
        pswd=raw_input('%s\'s password : '%user)
    else:
        print('%s\'s password : '%user)
        sh('stty -echo')
        pswd=raw_input()
        sh('stty echo')
        print(encodestring(sha256(pswd).digest()))
    return pswd


def hex2dec(x):
    try:
        l=int(x,16)
        print(l)
    except Exception as e:
        print(e)


def hex2bin(x):
    try:
        b=bin(int(x,16))
        print(b)
    except Exception as e:
        print(e)



def funnycrypt(dico,h):
    """funnycrypt(dico,h)"""
    import crypt,time
    from datetime import timedelta
    if len(h) != 106:
        print('Hash not valid.')
        return
    count=0
    salt=h[:20]
    tps=time.time()
    with open(dico) as f:
        for i in f.readlines():
            count+=1
            pswd=crypt.crypt(i.rstrip(),salt)
            if pswd==h:
                print('\nPassword found :\n\t\t%s'%i)
                break
    tot=round(time.time() - tps,3)
    print('%d tests in %.3f sec.'%(count,tot))
    print(timedelta(seconds=tot))
    
    
    
def brutezip(zfile,dico):
    """brutezip(zfile,dico)"""
    import zipfile
    from datetime import timedelta
    count=0
    tps=time.time()
    try:
        z=zipfile.ZipFile(zfile)
        with open(dico) as f:
            for i in f.readlines():
                count+=1
                try:
                    z.extractall(pwd=i.rstrip())
                    tot=round(time.time()-tps,3)
                    print('%d tests in %.3f sec.'%(count,tot))
                    print(timedelta(seconds=tot))
                    print('Password found : ')
                    return i.rstrip()
                except Exception:
                    pass
    except Exception as e:
        print(e)



def reverselookup(ip):
    """reverselookup(ip|domain)"""
    try:
        r=socket.gethostbyaddr(ip)
        print(r[0])
        print(r[2])
    except Exception as e:
        print(e)



def dnsrequest(domain):
    """dnsrequest(domain)"""
    import DNS
    DNS.DiscoverNameServers()
    r=DNS.Request()
    res=r.req(name=domain,qtype=255)
    for i in res.answers:
	    print('%-5s %s'%(i['typename'],i['data']))
    if not res.answers: print('Domain not found')



def quadArecord(dom):
    """quadArecord(domain)"""
    try:
        ip6=socket.getaddrinfo(dom,None,socket.AF_INET6)[1][4][0]
        return ip6
    except Exception as e:
        print('%s\n%s not found'%(e,dom))



def hashme(algo,me):
    """hashme(algo,str(me))"""
    import hashlib
    try:
        return {
            "md5"    : lambda: hashlib.md5(me).hexdigest(),    
            "sha1"   : lambda: hashlib.sha1(me).hexdigest(),
            "sha224" : lambda: hashlib.sha224(me).hexdigest(),
            "sha256" : lambda: hashlib.sha256(me).hexdigest(),
            "sha384" : lambda: hashlib.sha384(me).hexdigest(),
            "sha512" : lambda: hashlib.sha512(me).hexdigest(),
        }.get(algo)()
    except TypeError:
        print('Hash functions available :')
        for i in hashlib.algorithms_guaranteed:
            print(i)

        
def hashfile(algo,fic):
    """hashfile(algo,file)"""
    try:
        with open(fic,'r') as f:
            dat=f.read()
        #print('%s  %s'%(hashme(algo,dat),fic))
        return hashme(algo,dat)
    except Exception as e:
        print(e)


def findandhash(path,fic,algo):
    """findandhash(path,file*name,algo)"""
    res=[]
    for r,d,f in os.walk(os.path.expanduser(path)):
        #if fic in f:
        #    h=os.path.join(r,fic)
        #    print('\n'+h)
        #    print(hashfile(algo,h))
        for j in f:
            if fnmatch(j,fic):
               res.append(os.path.join(r,j))
    for i in res:
        print('\n'+i)
        print(hashfile(algo,i))
            
            
            


lenhash={
    "md5"   : 32,
    "sha1"  : 40,
    "sha224": 56,
    "sha384": 96,
    "sha256": 64,
    "sha512": 128,
    }

def shathat(dico,h):                                                         
    """shathat(dico,h)"""
    import hashlib,time
    from datetime import timedelta
    #print('Hash functions available :')
    #ls=[i for i in hashlib.algorithms_guaranteed]
    #for i in ls:
    #    print(i)
    #algo=raw_input('Hash function : ')
    #if algo not in ls or len(h) != lenhash.get(algo): 
    #    print('Check algorithm ...')
    #    return
    l=len(h)
    try:
        algo=lenhash.keys()[lenhash.values().index(l)]
    except ValueError:
        print('Hash not valid ...')
        return
    print("Algorithm : %s\n"%algo)
    try:
        tps=time.time()
        count=0
        with open(dico,'r') as f:
            for i in f.readlines():
                count+=1                                                       
                r=hashme(algo,i.rstrip())
                if r==h:
                    print('%s(%s)=%s'%(algo,i.rstrip(),r))
                    tot=round(time.time()-tps,3)
                    print('%s tests in %.3f sec.'%(count,tot))
                    print(timedelta(seconds=tot))
                    return i.rstrip()
            print('Not found in %s. %s tests'%(dico,count))
    except Exception as e:
        print(e)


def deltadirectory(src,dst):
    """deltadirectory(src_dir,dst_dir) (abs. path)"""
    import shutil
    try:
    	r1=[i for i in os.listdir(src)]
    	r2=[i for i in os.listdir(dst)]
    except OSError as e:
    	print(e)
    	return
    
    ls=[]
    cmd="cp -rp "+src+"/* "+dst+"/"
    for i in os.listdir(src):
        if os.path.isdir(src+"/"+i):
            print('Le contenu du répertoire "%s" ne sera pas analysé ...'%i)
    	if i not in os.listdir(dst):
    		ls.append(i)
    for j in sorted(ls):
    	print('Only in %s : %s'%(src,j))
    
    if len(ls)==0:
    	print('Rien à copier ...')
    	return
    
    q=raw_input("\nCopier dans %s (O/n) : "%dst)
    
    if q=="" or q.lower().startswith('o'):
      for i in r1:
        if i not in sorted(r2):
    	    os.chdir(src)
            try:
                shutil.copy2(i,dst)
            except IOError as e:
                if not sys.platform.startswith('wind'):
                    pass
                    os.system(cmd)
                else:
                    print(e)
    	    print('%s copié dans %s'%(i,dst))
    else: 
        print('Abandon')
        return



def sshcmd(user,ip,port=22):
    """sshcmd(user,ip)"""
    from pexpect import pxssh
    try:  
      try:
          s=pxssh.pxssh()
          pswd=enterpassword(user)
          s.login(ip,user,pswd,port,auto_prompt_reset=False)
          #s.prompt()
          #print(s.before)
          s.interact()
      except Exception as e:
          print(e)
          return
      #while True:
      #    cmd=raw_input(' > ')
      #    if not cmd: 
      #        print('Logout')
      #        return
      #    s.sendline(cmd)
      #    s.prompt()
      #    print(s.before)
    except Exception: 
      return




def scanports(ip,*args):
	socket.setdefaulttimeout(5)
	for i in args:
		try:
			s=socket.socket()
			r=s.connect_ex((ip,int(i)))
			if r==0:
				try:
					print('%-16s on %-5d   Open (%s)'%(ip,i,socket.getservbyport(i)))
				except Exception as e:
					print('%-16s on %-5s   Open (%s)'%(ip,i,e))
				finally:
					s.close()
			else:
				continue
#				if errno.errorcode[r]=="ECONNREFUSED":
#					continue
#				if errno.errorcode[r]=="EHOSTUNREACH":
#					print('%s : Host unreachable ...'%ip)
#					return
#				if errno.errorcode[r]=="ENETUNREACH":
#					print('Network unreachable.')
#					return
		except Exception as e:
			print(e)
			pass



def exploresqlitedb(db_file):
	import sqlite3
	try:
		with open(db_file) as f:
			f.read(256)
	except IOError as e:
		print(e)
		return
	try:
		db=sqlite3.connect(db_file)
		c=db.cursor()
		c.execute('select * from sqlite_master')
		for i in c.fetchall():
			print(i)
	except Exception as e:
		print(e)
		return
	while True:
		tab=raw_input('\nTable Name : ')
		if not tab: return
		try:
			c.execute('select * from '+tab)
			for i in c.fetchall():
				print(i)
		except Exception as e:
			print(e)
			pass




