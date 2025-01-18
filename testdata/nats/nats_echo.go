package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	// 定义命令行参数
	natsURL := flag.String("nats", nats.DefaultURL, "NATS server URL")
	subject := flag.String("subject", "demo.subject", "Subject to publish messages to")
	echoSubject := flag.String("echo", "echo.subject", "Subject to receive echo messages")
	count := flag.Int("count", 0, "Number of messages to send (0 for infinite)")
	interval := flag.Duration("interval", 5*time.Second, "Interval between messages")
	flag.Parse()

	// 连接到NATS服务器
	nc, err := nats.Connect(*natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// 订阅回显主题
	sub, err := nc.SubscribeSync(*echoSubject)
	if err != nil {
		log.Fatal(err)
	}

	// 发送消息并接收回显
	for i := 0; *count == 0 || i < *count; i++ {
		msg := fmt.Sprintf("Hello NATS! %d", i)
		if err := nc.Publish(*subject, []byte(msg)); err != nil {
			log.Fatal(err)
		}
		log.Printf("Sent message: %s\n", msg)

		// 等待回显消息
		echoMsg, err := sub.NextMsg(10 * time.Second)
		if err != nil {
			log.Println("Timeout waiting for echo message")
			continue
		}

		log.Printf("Received echo: %s\n", string(echoMsg.Data))
		time.Sleep(*interval)
	}
}
