from rocketmq.client import Producer, Message, PushConsumer


def send_message():
    producer = Producer("TestProducerGroup")
    producer.set_namesrv_addr("127.0.0.1:9876")
    producer.start()

    msg = Message("TestTopic")
    msg.set_keys("messageKey")
    msg.set_tags("messageTag")
    msg.set_body("Hello RocketMQ")
    result = producer.send_sync(msg)
    print(f"Message sent: {result}")
    producer.shutdown()


def consume_message():
    consumer = PushConsumer("TestConsumerGroup")
    consumer.set_namesrv_addr("127.0.0.1:9876")

    def callback(msg):
        print(f"Message received: {msg.body.decode()}")
        return True

    consumer.subscribe("TestTopic", callback)
    consumer.start()
    print("Consumer started. Press Ctrl+C to exit...")
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        consumer.shutdown()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "consume":
        consume_message()
    else:
        send_message()
