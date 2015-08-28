package main

import (
	"fmt"
	"net"
	"os"
	"io/ioutil"
	"log/syslog"

	"golang.org/x/crypto/ssh"
  log "github.com/Sirupsen/logrus"
  logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
  "github.com/rifflock/lfshook"
)

func setupLogging() {
  logLevel := log.InfoLevel
  if os.Getenv("DEBUG") == "true" { logLevel = log.DebugLevel }
  log.SetLevel(logLevel)

	logrusFileHook := lfshook.NewHook(lfshook.PathMap{
	  log.InfoLevel : "/var/log/sshoney.log",
	  log.WarnLevel : "/var/log/sshoney.log",
	  log.ErrorLevel : "/var/log/sshoney.log",
	  log.FatalLevel : "/var/log/sshoney.log",
	  log.PanicLevel : "/var/log/sshoney.log",
  })
	log.AddHook(logrusFileHook)

	logrusSysLogHook, err := logrus_syslog.NewSyslogHook("", "localhost", syslog.LOG_INFO, "sshoney")
	if err != nil { log.Fatalf("Failed to add syslog logrus hook - %s", err) }
  log.AddHook(logrusSysLogHook)

	log.SetFormatter(&log.TextFormatter{DisableColors: true})
}

func main() {
  setupLogging()

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	privateBytes, err := ioutil.ReadFile("./host.key")
	if err != nil { log.Fatal("Failed to load private key ./host.key.  Run make gen_ssh_key") }

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil { log.Fatal("Failed to parse private key") }
	sshConfig.AddHostKey(private)

  port := "2222"
  if os.Getenv("PORT") != "" {
    port = os.Getenv("PORT")
  }

  portComplete := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp4", portComplete)
	if err != nil { log.Fatalf("failed to listen on *:%s", port) }

	log.Printf("listening on %s", port)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Debugf("failed to accept incoming connection (%s)", err)
			continue
		}

		log.Debugf("new TCP connection from %s", tcpConn.RemoteAddr())

		sshConn, _, _, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Debugf("failed to handshake (%s)", err)
			continue
		}

		log.Printf("new SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

    sshConn.Close()
	}
}
