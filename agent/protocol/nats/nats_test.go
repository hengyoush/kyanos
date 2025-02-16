package nats

import (
	"strings"
	"testing"
)

func TestInfoParser(t *testing.T) {
	payload := []byte("INFO {\"server_id\":\"test_id\",\"server_name\":\"test_name\",\"version\":\"1.0.0\",\"go_version\":\"1.15\",\"host\":\"localhost\",\"port\":4222,\"max_payload\":1048576,\"tls_required\":false}\r\n")
	parser := &Info{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if msg.ServerID != "test_id" {
		t.Errorf("Expected ServerID to be 'test_id', got '%s'", msg.ServerID)
	}
	if msg.ServerName != "test_name" {
		t.Errorf("Expected ServerName to be 'test_name', got '%s'", msg.ServerName)
	}
}

func TestConnectParser(t *testing.T) {
	payload := []byte("CONNECT {\"verbose\":true,\"pedantic\":false,\"tls_required\":true,\"name\":\"test_client\",\"version\":\"1.0.0\"}\r\n")
	parser := &Connect{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if !msg.Verbose {
		t.Errorf("Expected Verbose to be true, got %v", msg.Verbose)
	}
}

func TestPubParser(t *testing.T) {
	var pubTests = []struct {
		Name          string
		Bytes         []byte
		Subject       string
		ReplyTo       string
		Payload       string
		ExpectedError bool
	}{
		{
			Name:    "PUB with payload",
			Bytes:   []byte("PUB FOO 11\r\nHello NATS!\r\n"),
			Subject: "FOO",
			Payload: "Hello NATS!",
		},
		{
			Name:    "PUB with reply-to and payload",
			Bytes:   []byte("PUB FRONT.DOOR JOKE.22 11\r\nKnock Knock\r\n"),
			Subject: "FRONT.DOOR",
			ReplyTo: "JOKE.22",
			Payload: "Knock Knock",
		},
		{
			Name:    "PUB with empty payload",
			Bytes:   []byte("PUB NOTIFY 0\r\n\r\n"),
			Subject: "NOTIFY",
			Payload: "",
		},
		{
			Name:          "PUB with invalid payload length",
			Bytes:         []byte("PUB INVALID 6\r\nHello\r\n"),
			Subject:       "INVALID",
			Payload:       "Hello",
			ExpectedError: true,
		},
		{
			Name:          "PUB with invalid payload length",
			Bytes:         []byte("PUB INVALID 2\r\nHello\r\n"),
			Subject:       "INVALID",
			Payload:       "Hello",
			ExpectedError: true,
		},
		{
			Name:          "PUB with missing payload",
			Bytes:         []byte("PUB MISSING 5\r\n"),
			Subject:       "MISSING",
			Payload:       "",
			ExpectedError: true,
		},
	}

	parser := &Pub{}

	for _, tt := range pubTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Subject != tt.Subject {
				t.Errorf("Expected Subject to be '%s', got '%s'", tt.Subject, msg.Subject)
			}
			if tt.ReplyTo != "" && msg.ReplyTo != tt.ReplyTo {
				t.Errorf("Expected ReplyTo to be '%s', got '%s'", tt.ReplyTo, msg.ReplyTo)
			}
			if string(msg.Payload) != tt.Payload {
				t.Errorf("Expected Payload to be '%s', got '%s'", tt.Payload, msg.Payload)
			}
		})
	}
}

func TestHpubParser(t *testing.T) {
	var hpubTests = []struct {
		Name          string
		Bytes         []byte
		Subject       string
		ReplyTo       string
		HeaderVersion string
		Headers       map[string]string
		Payload       string
		ExpectedError bool
	}{
		{
			Name:          "HPUB with headers and payload",
			Bytes:         []byte("HPUB FOO 22 33\r\nNATS/1.0\r\nBar: Baz\r\n\r\nHello NATS!\r\n"),
			Subject:       "FOO",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"Bar": "Baz"},
			Payload:       "Hello NATS!",
		},
		{
			Name:          "HPUB with reply-to, multiple headers, and payload",
			Bytes:         []byte("HPUB FRONT.DOOR JOKE.22 45 56\r\nNATS/1.0\r\nBREAKFAST: donut\r\nLUNCH: burger\r\n\r\nKnock Knock\r\n"),
			Subject:       "FRONT.DOOR",
			ReplyTo:       "JOKE.22",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"BREAKFAST": "donut", "LUNCH": "burger"},
			Payload:       "Knock Knock",
		},
		{
			Name:          "HPUB with empty payload",
			Bytes:         []byte("HPUB NOTIFY 22 22\r\nNATS/1.0\r\nBar: Baz\r\n\r\n\r\n"),
			Subject:       "NOTIFY",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"Bar": "Baz"},
			Payload:       "",
		},
		{
			Name:          "HPUB with multiple headers and empty payload",
			Bytes:         []byte("HPUB MORNING.MENU 47 47\r\nNATS/1.0\r\nBREAKFAST: donut\r\nBREAKFAST: eggs\r\n\r\n\r\n"),
			Subject:       "MORNING.MENU",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"BREAKFAST": "donut, eggs"},
			Payload:       "",
		},
		{
			Name:          "HPUB with invalid header format",
			Bytes:         []byte("HPUB INVALID 22 33\r\nNATS/1.0\r\nInvalidHeader\r\n\r\nHello NATS!\r\n"),
			Subject:       "INVALID",
			HeaderVersion: "NATS/1.0",
			ExpectedError: true,
		},
		{
			Name:          "HPUB with missing payload",
			Bytes:         []byte("HPUB MISSING 22 33\r\nNATS/1.0\r\nBar: Baz\r\n\r\n"),
			Subject:       "MISSING",
			HeaderVersion: "NATS/1.0",
			ExpectedError: true,
		},
	}

	parser := &Hpub{}

	for _, tt := range hpubTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Subject != tt.Subject {
				t.Errorf("Expected Subject to be '%s', got '%s'", tt.Subject, msg.Subject)
			}
			if tt.ReplyTo != "" && msg.ReplyTo != tt.ReplyTo {
				t.Errorf("Expected ReplyTo to be '%s', got '%s'", tt.ReplyTo, msg.ReplyTo)
			}
			if msg.HeaderVersion != tt.HeaderVersion {
				t.Errorf("Expected HeaderVersion to be '%s', got '%s'", tt.ReplyTo, msg.HeaderVersion)
			}
			if len(tt.Headers) > 0 {
				for key, value := range tt.Headers {
					if strings.Join(msg.Headers[key], ", ") != value {
						t.Errorf("Expected header '%s' to be '%s', got '%s'", key, value, strings.Join(msg.Headers[key], ", "))
					}
				}
			}
			if string(msg.Payload) != tt.Payload {
				t.Errorf("Expected Payload to be '%s', got '%s'", tt.Payload, msg.Payload)
			}
		})
	}
}

func TestSubParser(t *testing.T) {
	var subTests = []struct {
		Name          string
		Bytes         []byte
		Subject       string
		QueueGroup    string
		Sid           string
		ExpectedError bool
	}{
		{
			Name:    "SUB with subject and sid",
			Bytes:   []byte("SUB test.subject 123\r\n"),
			Subject: "test.subject",
			Sid:     "123",
		},
		{
			Name:       "SUB with subject, queue group, and sid",
			Bytes:      []byte("SUB test.subject test.queue 123\r\n"),
			Subject:    "test.subject",
			QueueGroup: "test.queue",
			Sid:        "123",
		},
		{
			Name:          "SUB with missing sid",
			Bytes:         []byte("SUB test.subject\r\n"),
			Subject:       "test.subject",
			ExpectedError: true,
		},
	}

	parser := &Sub{}

	for _, tt := range subTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Subject != tt.Subject {
				t.Errorf("Expected Subject to be '%s', got '%s'", tt.Subject, msg.Subject)
			}
			if msg.QueueGroup != tt.QueueGroup {
				t.Errorf("Expected QueueGroup to be '%s', got '%s'", tt.QueueGroup, msg.QueueGroup)
			}
			if msg.Sid != tt.Sid {
				t.Errorf("Expected Sid to be '%s', got '%s'", tt.Sid, msg.Sid)
			}
		})
	}
}

func TestUnsubParser(t *testing.T) {
	var unsubTests = []struct {
		Name          string
		Bytes         []byte
		Sid           string
		MaxMessages   int
		ExpectedError bool
	}{
		{
			Name:        "UNSUB with sid",
			Bytes:       []byte("UNSUB 123\r\n"),
			Sid:         "123",
			MaxMessages: -1,
		},
		{
			Name:        "UNSUB with sid and max messages",
			Bytes:       []byte("UNSUB 123 10\r\n"),
			Sid:         "123",
			MaxMessages: 10,
		},
		{
			Name:          "UNSUB with missing sid",
			Bytes:         []byte("UNSUB\r\n"),
			ExpectedError: true,
		},
		{
			Name:          "UNSUB with invalid max messages",
			Bytes:         []byte("UNSUB 123 invalid\r\n"),
			ExpectedError: true,
		},
	}
	parser := &Unsub{}

	for _, tt := range unsubTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Sid != tt.Sid {
				t.Errorf("Expected Sid to be '%s', got '%s'", tt.Sid, msg.Sid)
			}
		})
	}
}

func TestMsgParser(t *testing.T) {
	var msgTests = []struct {
		Name          string
		Bytes         []byte
		Subject       string
		Sid           string
		ReplyTo       string
		Payload       string
		ExpectedError bool
	}{
		{
			Name:    "MSG with subject, sid, and payload",
			Bytes:   []byte("MSG test.subject 123 5\r\nhello\r\n"),
			Subject: "test.subject",
			Sid:     "123",
			Payload: "hello",
		},
		{
			Name:    "MSG with subject, sid, reply-to, and payload",
			Bytes:   []byte("MSG test.subject 123 test.reply 5\r\nhello\r\n"),
			Subject: "test.subject",
			Sid:     "123",
			ReplyTo: "test.reply",
			Payload: "hello",
		},
		{
			Name:          "MSG with missing payload",
			Bytes:         []byte("MSG test.subject 123 5\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			ExpectedError: true,
		},
		{
			Name:          "MSG with invalid payload length",
			Bytes:         []byte("MSG test.subject 123 6\r\nhello\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			ExpectedError: true,
		},
	}
	parser := &Msg{}

	for _, tt := range msgTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Subject != tt.Subject {
				t.Errorf("Expected Subject to be '%s', got '%s'", tt.Subject, msg.Subject)
			}
			if msg.Sid != tt.Sid {
				t.Errorf("Expected Sid to be '%s', got '%s'", tt.Sid, msg.Sid)
			}
			if tt.ReplyTo != "" && msg.ReplyTo != tt.ReplyTo {
				t.Errorf("Expected ReplyTo to be '%s', got '%s'", tt.ReplyTo, msg.ReplyTo)
			}
			if string(msg.Payload) != tt.Payload {
				t.Errorf("Expected Payload to be '%s', got '%s'", tt.Payload, msg.Payload)
			}
		})
	}
}

func TestHmsgParser(t *testing.T) {
	var hmsgTests = []struct {
		Name          string
		Bytes         []byte
		Subject       string
		Sid           string
		ReplyTo       string
		HeaderVersion string
		Headers       map[string]string
		Payload       string
		ExpectedError bool
	}{
		{
			Name:          "HMSG with subject, sid, headers, and payload",
			Bytes:         []byte("HMSG test.subject 123 24 29\r\nNATS/1.0\r\nKey: Value\r\n\r\nhello\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"Key": "Value"},
			Payload:       "hello",
		},
		{
			Name:          "HMSG with subject, sid, reply-to, headers, and payload",
			Bytes:         []byte("HMSG test.subject 123 test.reply 24 29\r\nNATS/1.0\r\nKey: Value\r\n\r\nhello\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			ReplyTo:       "test.reply",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"Key": "Value"},
			Payload:       "hello",
		},
		{
			Name:          "HMSG with empty payload",
			Bytes:         []byte("HMSG NOTIFY 123 22 22\r\nNATS/1.0\r\nBar: Baz\r\n\r\n\r\n"),
			Subject:       "NOTIFY",
			Sid:           "123",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"Bar": "Baz"},
			Payload:       "",
		},
		{
			Name:          "HMSG with multiple headers and empty payload",
			Bytes:         []byte("HMSG MORNING.MENU 123 47 47\r\nNATS/1.0\r\nBREAKFAST: donut\r\nBREAKFAST: eggs\r\n\r\n\r\n"),
			Subject:       "MORNING.MENU",
			Sid:           "123",
			HeaderVersion: "NATS/1.0",
			Headers:       map[string]string{"BREAKFAST": "donut, eggs"},
			Payload:       "",
		},
		{
			Name:          "HMSG with invalid header format",
			Bytes:         []byte("HMSG test.subject 123 20 25\r\nNATS/1.0\r\nInvalidHeader\r\n\r\nhello\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			HeaderVersion: "NATS/1.0",
			ExpectedError: true,
		},
		{
			Name:          "HMSG with missing payload",
			Bytes:         []byte("HMSG test.subject 123 20 25\r\nNATS/1.0\r\nKey: Value\r\n\r\n"),
			Subject:       "test.subject",
			Sid:           "123",
			HeaderVersion: "NATS/1.0",
			ExpectedError: true,
		},
	}

	parser := &Hmsg{}

	for _, tt := range hmsgTests {
		t.Run(tt.Name, func(t *testing.T) {
			msg, prased := parser.ParseData(tt.Bytes)

			if tt.ExpectedError {
				if prased < 0 {
					t.Errorf("Expected ParseState to be Failure, got Success")
				}
				return
			}
			if prased < 0 {
				t.Errorf("Expected ParseState to be Success, got %v", prased)
			}
			if msg == nil {
				t.Fatal("Expected Result to be Success, got nil")
			}
			if msg.Subject != tt.Subject {
				t.Errorf("Expected Subject to be '%s', got '%s'", tt.Subject, msg.Subject)
			}
			if msg.Sid != tt.Sid {
				t.Errorf("Expected Sid to be '%s', got '%s'", tt.Sid, msg.Sid)
			}
			if tt.ReplyTo != "" && msg.ReplyTo != tt.ReplyTo {
				t.Errorf("Expected ReplyTo to be '%s', got '%s'", tt.ReplyTo, msg.ReplyTo)
			}
			if msg.HeaderVersion != tt.HeaderVersion {
				t.Errorf("Expected HeaderVersion to be '%s', got '%s'", tt.ReplyTo, msg.HeaderVersion)
			}
			if len(tt.Headers) > 0 {
				for key, value := range tt.Headers {
					if strings.Join(msg.Headers[key], ", ") != value {
						t.Errorf("Expected header '%s' to be '%s', got '%s'", key, value, strings.Join(msg.Headers[key], ", "))
					}
				}
			}
			if string(msg.Payload) != tt.Payload {
				t.Errorf("Expected Payload to be '%s', got '%s'", tt.Payload, msg.Payload)
			}
		})
	}
}

func TestPingParser(t *testing.T) {
	payload := []byte("PING\r\n")
	parser := &Ping{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if msg.ProtocolCode != PING {
		t.Errorf("Expected ProtocolCode to be PING, got %v", msg.ProtocolCode)
	}
}

func TestPongParser(t *testing.T) {
	payload := []byte("PONG\r\n")
	parser := &Pong{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if msg.ProtocolCode != PONG {
		t.Errorf("Expected ProtocolCode to be PONG, got %v", msg.ProtocolCode)
	}
}

func TestOkParser(t *testing.T) {
	payload := []byte("+OK\r\n")
	parser := &Ok{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if msg.ProtocolCode != OK {
		t.Errorf("Expected ProtocolCode to be OK, got %v", msg.ProtocolCode)
	}
}

func TestErrParser(t *testing.T) {
	payload := []byte("-ERR 'Unknown Protocol Operation'\r\n")
	parser := &Err{}
	msg, prased := parser.ParseData(payload)

	if prased < 0 {
		t.Errorf("Expected ParseState to be Success, got %v", prased)
	}
	if msg == nil {
		t.Fatal("Expected Result to be Success, got nil")
	}
	if msg.ErrorMessage != "'Unknown Protocol Operation'" {
		t.Errorf("Expected ErrorMessage to be 'test error message', got '%s'", msg.ErrorMessage)
	}
}
