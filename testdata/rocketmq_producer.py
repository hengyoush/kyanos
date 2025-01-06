from rocketmq.client import Producer, Message

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
