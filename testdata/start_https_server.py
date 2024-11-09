import http.server
import ssl
from socketserver import ThreadingMixIn

# 创建自定义的 HTTP 服务器类，支持线程以处理多个连接
class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    # 设置 allow_reuse_address 以支持长连接
    allow_reuse_address = True

class KeepAliveHandler(http.server.SimpleHTTPRequestHandler):
    # 设置响应头以启用长连接

    # 重写 `do_GET` 方法处理 GET 请求
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Length", str(len("Hello, this is an HTTPS server with keep-alive support!")))
        self.end_headers()
        self.wfile.write(b"Hello, this is an HTTPS server with keep-alive support!")

# 服务器地址和端口
server_address = ('localhost', 4443)
httpd = ThreadedHTTPServer(server_address, KeepAliveHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='server.pem', keyfile='server.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("HTTPS server running on https://localhost:4443 with keep-alive support")
httpd.serve_forever()
