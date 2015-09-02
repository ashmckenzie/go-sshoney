package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"io/ioutil"
	"log/syslog"

  log "github.com/Sirupsen/logrus"
  logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"golang.org/x/crypto/ssh"
  "github.com/rifflock/lfshook"
  "github.com/codegangsta/cli"
	// "github.com/davecgh/go-spew/spew"
)

func setupLogging(logToSyslog bool, syslogAddr string, syslogProgramName string, logFile string) {
  logLevel := log.InfoLevel
  if os.Getenv("DEBUG") == "true" { logLevel = log.DebugLevel }
  log.SetLevel(logLevel)

	log.SetFormatter(&log.TextFormatter{DisableColors: true})

	if (logToSyslog)      { setupSyslogLogging(syslogAddr, syslogProgramName) }
	if (len(logFile) > 0) { setupFileLogging(logFile) }
}

func setupSyslogLogging(syslogAddr string, syslogProgramName string) {
	log.Printf("Logging to syslog addr=[%s], program_name=[%s]", syslogAddr, syslogProgramName)
	logrusSysLogHook, err := logrus_syslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, syslogProgramName)
	if err != nil { log.Fatalf("Failed to add syslog logrus hook - %s", err) }
	log.AddHook(logrusSysLogHook)
}

func setupFileLogging(logFile string) {
	log.Printf("Logging to file=[%s]", logFile)
	logrusFileHook := lfshook.NewHook(lfshook.PathMap{
	  log.InfoLevel : logFile, log.WarnLevel : logFile, log.ErrorLevel : logFile, log.FatalLevel : logFile, log.PanicLevel : logFile,
  })
	log.AddHook(logrusFileHook)
}

func setupSSHListener(port string, hostKey string) (ssh.ServerConfig, net.Listener) {
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			remoteAddr := c.RemoteAddr().String()
			ip := remoteAddr[0:strings.Index(remoteAddr, ":")]
			log.Printf("SSH connection from ip=[%s], username=[%s], password=[%s], version=[%s]", ip, c.User(), pass, c.ClientVersion())
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	privateBytes, err := ioutil.ReadFile(hostKey)
	if err != nil { log.Fatalf("Failed to load private key %s.  Run make gen_ssh_key %s", hostKey, hostKey) }

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil { log.Fatal("Failed to parse private key") }
	sshConfig.AddHostKey(private)

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
		sshConn.Close()
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "sshoney"
	app.Usage = "SSH honeypot"
	app.Version = "0.1.0"

	app.Flags = []cli.Flag {
		cli.BoolFlag{ Name: "log-to-syslog", Usage: "log to syslog" },
		cli.StringFlag{
	    Name: "port",
	    Usage: "port to listen on",
			Value: "2222",
			EnvVar: "PORT",
	  },
		cli.StringFlag{
	    Name: "syslog-addr",
	    Usage: "host:port of the syslog server",
			Value: "localhost:514",
			EnvVar: "SYSLOG_ADDR",
	  },
		cli.StringFlag{
	    Name: "syslog-program-name",
	    Usage: "syslog program name to use",
			Value: "sshoney",
			EnvVar: "SYSLOG_PROGRAM_NAME",
	  },
		cli.StringFlag{
	    Name: "host-key",
	    Usage: "SSH private host key",
			Value: "host.key",
			EnvVar: "HOST_KEY",
	  },
	  cli.StringFlag{
	    Name: "log-file",
	    Usage: "path to logfile",
			EnvVar: "LOG_FILE",
	  },
	}

	app.Action = func(c *cli.Context) {
		setupLogging(c.Bool("log-to-syslog"), c.String("syslog-addr"), c.String("syslog-program-name"), c.String("log-file"))
		sshConfig, listener := setupSSHListener(c.String("port"), c.String("host-key"))
		processConnections(&sshConfig, listener)
	}

	app.Run(os.Args)
}
