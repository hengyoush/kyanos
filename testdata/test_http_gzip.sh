#!/usr/bin/env bash

. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTP_CLIENT_LNAME="${FILE_PREFIX}_http_gzip_client.log"
HTTP_SERVER_LNAME="${FILE_PREFIX}_http_gzip_server.log"
NGINX_GZIP_TEST_LNAME="${FILE_PREFIX}_nginx_gzip_test.log"

function test_http_gzip_client() {
    # 测试客户端接收 gzip 压缩内容
    pip install --break-system-packages requests || true
    # 使用 httpbin.org 的 gzip 端点，它会返回 gzip 压缩的响应
    timeout 30 python3 ./testdata/request_http.py 60 'http://httpbin.org/gzip' &
    echo "after python3 exec"
    date
    sleep 10
    echo "after sleep 10s"
    date
    timeout 30 ${CMD} watch --debug-output http --remote-ports 80 2>&1 | tee "${HTTP_CLIENT_LNAME}" &
    wait

    cat "${HTTP_CLIENT_LNAME}"
    # 检查是否包含 gzip 相关信息
    cat "${HTTP_CLIENT_LNAME}" | grep -E "Content-Encoding: gzip|gzipped: true"
}

function test_nginx_gzip_server() {
    # 使用 nginx 配置 gzip 压缩
    cat > ./testdata/nginx_gzip.conf << 'EOF'
events {
    worker_connections 1024;
}
http {
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    gzip_min_length 1000;
    server {
        listen 8080;
        location / {
            root /usr/share/nginx/html;
            # 创建一个大文件以确保触发 gzip
            location /test.txt {
                return 200 'This is a test file with repeated content to ensure it gets compressed. This is a test file with repeated content to ensure it gets compressed. This is a test file with repeated content to ensure it gets compressed.';
                add_header Content-Type text/plain;
            }
        }
    }
}
EOF

    # 启动配置了 gzip 的 nginx 服务器
    cid=$(docker run --rm -d -p 8080:8080 -v ./testdata/nginx_gzip.conf:/etc/nginx/nginx.conf:ro nginx:latest)
    export cid
    echo $cid
    
    # 监控 8080 端口的流量
    timeout 30 ${CMD} watch --debug-output http --local-ports 8080 2>&1 | tee "${NGINX_GZIP_TEST_LNAME}" &
    sleep 10
    
    # 发送请求，要求 gzip 压缩
    curl -H "Accept-Encoding: gzip" http://localhost:8080/test.txt -v || true
    sleep 3
    docker stop $cid
    wait
    
    cat "${NGINX_GZIP_TEST_LNAME}"
    # 检查是否包含 gzip 相关信息
    check_patterns_in_file "${NGINX_GZIP_TEST_LNAME}" "Content-Encoding: gzip"
}

function main() {
    test_http_gzip_client
    test_nginx_gzip_server
}

main 
