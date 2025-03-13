#!/usr/bin/env python3
import requests
import time
import sys

# 创建一个Session对象
session = requests.Session()

# 设置请求的URL和循环次数
url = sys.argv[2]
count = int(sys.argv[1])

# 设置请求头，声明接受 gzip 压缩
session.headers.update({
    'Accept-Encoding': 'gzip, deflate'
})

# 循环发送请求
for i in range(count):
    try:
        # 发起HTTP请求
        response = session.get(url)
        
        # 检查请求是否成功
        if response.status_code == 200:
            print(f'请求 {i+1}：成功')
            # 打印响应头和内容
            print(f'响应头：')
            print(response.headers)
            print(f'响应内容（前200字符）：')
            print(response.text[:200])
            # 特别检查是否使用了 gzip 压缩
            if 'gzip' in response.headers.get('Content-Encoding', ''):
                print('响应使用了 gzip 压缩')
        else:
            print(f'请求 {i+1}：失败，状态码：{response.status_code}')
    
    except requests.exceptions.RequestException as e:
        # 打印异常信息
        print(f'请求 {i+1}：发生错误', e)
    
    # 休眠
    time.sleep(0.5)

# 关闭Session对象
session.close() 
