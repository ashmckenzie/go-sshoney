package main

import (
	"fmt"
	"net"
	"os"
	"io/ioutil"
	"log/syslog"

  log "github.com/Sirupsen/logrus"
  logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"golang.org/x/crypto/ssh"
  "github.com/rifflock/lfshook"
  // "github.com/codegangsta/cli"
)

func setupCLI() {
	// cli.NewApp().Run(os.Args)
}

func setupLogging() {
  logLevel := log.InfoLevel
  if os.Getenv("DEBUG") == "true" { logLevel = log.DebugLevel }
  log.SetLevel(logLevel)

	log.SetFormatter(&log.TextFormatter{DisableColors: true})

	setupFileLogging()
	setupSyslogLogging()
}

func setupFileLogging() {
	logrusFileHook := lfshook.NewHook(lfshook.PathMap{
	  log.InfoLevel : "/var/log/sshoney.log",
	  log.WarnLevel : "/var/log/sshoney.log",
	  log.ErrorLevel : "/var/log/sshoney.log",
	  log.FatalLevel : "/var/log/sshoney.log",
	  log.PanicLevel : "/var/log/sshoney.log",
  })
	log.AddHook(logrusFileHook)
}

func setupSyslogLogging() {
	logrusSysLogHook, err := logrus_syslog.NewSyslogHook("", "localhost", syslog.LOG_INFO, "sshoney")
	if err != nil { log.Fatalf("Failed to add syslog logrus hook - %s", err) }
	log.AddHook(logrusSysLogHook)
}

func setupSSHListener() (ssh.ServerConfig, net.Listener) {
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

	return *sshConfig, listener;
}

func processConnections(sshConfig *ssh.ServerConfig, listener net.Listener) {
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Debugf("failed to accept incoming connection (%s)", err)
			continue
		}
		go handleConnection(sshConfig, tcpConn)
	}
}

func handleConnection(sshConfig *ssh.ServerConfig, tcpConn net.Conn) {
	defer tcpConn.Close()

	log.Debugf("new TCP connection from %s", tcpConn.RemoteAddr())

	sshConn, _, _, err := ssh.NewServerConn(tcpConn, sshConfig)
	if err != nil {
		log.Debugf("failed to handshake (%s)", err)
	} else {
		log.Printf("new SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		sshConn.Close()
	}
}

func main() {
	setupCLI()
	setupLogging()
	sshConfig, listener := setupSSHListener()
	processConnections(&sshConfig, listener)
}
