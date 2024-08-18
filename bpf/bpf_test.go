package bpf

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var mockServerPort = 16660

type GracefulServer struct {
	Server           *http.Server
	shutdownFinished chan struct{}
	startCompleted   chan struct{}
}

func (s *GracefulServer) ListenAndServe() (err error) {
	if s.shutdownFinished == nil {
		s.shutdownFinished = make(chan struct{})
	}
	if s.startCompleted == nil {
		s.startCompleted = make(chan struct{})
	}

	s.startCompleted <- struct{}{}
	err = s.Server.ListenAndServe()
	if err == http.ErrServerClosed {
		// expected error after calling Server.Shutdown().
		err = nil
	} else if err != nil {
		err = fmt.Errorf("unexpected error from ListenAndServe: %w", err)
		return
	}

	log.Println("waiting for shutdown finishing...")
	<-s.shutdownFinished
	log.Println("shutdown finished")

	return
}

func (s *GracefulServer) WaitForExitingSignal(timeout time.Duration) {
	var waiter = make(chan os.Signal, 1) // buffered channel
	signal.Notify(waiter, syscall.SIGTERM, syscall.SIGINT)

	// blocks here until there's a signal
	<-waiter

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := s.Server.Shutdown(ctx)
	if err != nil {
		log.Println("shutting down: " + err.Error())
	} else {
		log.Println("shutdown processed successfully")
		close(s.shutdownFinished)
	}
}

func TestReadv(t *testing.T) {

	fmt.Sprintln("abc")
	time.Sleep(time.Second * 1)
	server := "106.54.223.172:" + fmt.Sprintf("%d", mockServerPort)
	connection, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法连接到服务器 %s: %v\n", server, err)
		return
	}
	defer connection.Close()
	tcpConn := connection.(*net.TCPConn)
	tcpConnV := reflect.ValueOf(*tcpConn)
	message := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	len1 := 7
	// file, err := tcpConn.File()
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "无法获取conn的File\n")
	// 	return
	// }
	fd := tcpConnV.FieldByName("conn").FieldByName("fd").Elem().FieldByName("pfd").FieldByName("Sysfd").Int()
	syscall.SetNonblock(int(fd), false)

	var iovecs [][]byte = [][]byte{[]byte(message[:len1]), []byte(message[len1:])}
	n, err := unix.Writev(int(fd), iovecs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Writev出错, err: %v\n", err)
		return
	} else {
		fmt.Fprintf(os.Stderr, "Writev完成, n: %d, fd: %v\n", n, fd)
	}

	// time.Sleep(time.Second * 1)
	var readVecs [][]byte = [][]byte{make([]byte, 50), make([]byte, 1000)}
	n, err = unix.Readv(int(fd), readVecs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Readv出错, err: %v\n", err)
		return
	} else {
		allBufs := append(readVecs[0], readVecs[1]...)
		fmt.Fprintf(os.Stderr, "Readv完成, n: %d\n, content: %s\n", n, string(allBufs))
	}

}

// EchoHandler echos back the request as a response
func EchoHandler(writer http.ResponseWriter, request *http.Request) {
	log.Println("Echoing back request made to " + request.URL.Path + " to client (" + request.RemoteAddr + ")")

	writer.Header().Set("Access-Control-Allow-Origin", "*")

	// allow pre-flight headers
	writer.Header().Set("Access-Control-Allow-Headers", "Content-Range, Content-Disposition, Content-Type, ETag")

	request.Write(writer)
}
