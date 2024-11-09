import requests
import time
import sys

# 创建一个Session对象
session = requests.Session()
# 可选：禁用 SSL 验证（仅用于测试自签名证书）
session.verify = False

# 设置请求的URL
url = sys.argv[2]
count = int(sys.argv[1])

# 设置循环次数，例如100次
for i in range(count):
    try:
        # 发起HTTPS请求
        response = session.get(url, verify=False)
        
        # 检查请求是否成功
        if response.status_code == 200:
            print(f'请求 {i+1}：成功')
            # 打印响应内容的前200个字符
            print(response.headers)
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