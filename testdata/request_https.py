import requests
import time
import sys

# 创建一个Session对象
session = requests.Session()

# 设置请求的URL
url = 'https://httpbin.org/headers'
count = int(sys.argv[1])

# 设置循环次数，例如100次
for i in range(count):
    try:
        # 发起HTTPS请求
        response = session.get(url)
        
        # 检查请求是否成功
        if response.status_code == 200:
            print(f'请求 {i+1}：成功')
            # 打印响应内容的前200个字符
            print(response.text[:200])
        else:
            print(f'请求 {i+1}：失败，状态码：{response.status_code}')
    
    except requests.exceptions.RequestException as e:
        # 打印异常信息
        print(f'请求 {i+1}：发生错误', e)
    
    # 休眠
    time.sleep(0.5)

# 关闭Session对象
session.close()