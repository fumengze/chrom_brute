**# brute_force.py**
使用selenium驱动chrom浏览器的暴力破解工具

**# 介绍：**
用于解决JS前端加密、token校验等问题，支持进程池，通过flask作为web接口，用于下发暴力破解任务

**# 使用方法：**
- 启动服务：python3 brute_force.py
- 启动服务后，访问http://127.0.0.1:5000/webhook?target=https://xx.xx.xx.xx&mode=2&fingerprint=123

**# 请求参数说明：**
- target参数是需要暴破的URL
mode参数是模式，只接收1、2、3这三个值，1、单用户内密码循环爆破 2、单密码内多用户循环爆破 3、用户和密码按每行顺序爆破
- fingerprint参数是暴破的字典名称，如果没有检测到传输过来的字典名称，就会使用默认字典。
字典目录为dict_pass和dict_user，目录中每个txt代表每个不同的字典，比如default_pass.txt的指纹名称是default，test_user.txt的指纹名称是test。
- input_user和input_pass参数可以不传值，默认会使用通用匹配规则匹配input标签。两个参数为input标签的id名称，代表用户名框和密码框。
程序设置说明：
- HOST参数配置为127.0.0.1只允许本机请求，0.0.0.0允许其他地址请求
- 程序里pool参数是进程池控制参数，程序里写的是10，请根据内存情况自行设置，建议8G内存不要超过10
- chrome_option.add_argument('--headless')参数默认是不开启的，去除#为开启无头浏览器模式	
- chrome_option.add_argument('--proxy-server=ip:port')，代理参数设置，默认不开启，去除#为使用代理，代理只能是http协议或https协议，不支持socks协议

# 环境：
- 安装chrom浏览器，根据浏览器的版本下载相应版本的chromedriver。
