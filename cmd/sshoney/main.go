package main

import (
	"log/syslog"
	"os"

	log "github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/ashmckenzie/sshoney"
	"github.com/codegangsta/cli"
	"github.com/rifflock/lfshook"
	// "github.com/davecgh/go-spew/spew"
)

func setupLogging(logToSyslog bool, syslogAddr string, syslogProgramName string, logFile string) {
	logLevel := log.InfoLevel
	if os.Getenv("DEBUG") == "true" {
		logLevel = log.DebugLevel
	}
	log.SetLevel(logLevel)

	log.SetFormatter(&log.TextFormatter{DisableColors: true})

	if logToSyslog {
		setupSyslogLogging(syslogAddr, syslogProgramName)
	}
	if len(logFile) > 0 {
		setupFileLogging(logFile)
	}
}

func setupSyslogLogging(syslogAddr string, syslogProgramName string) {
	log.Printf("Logging to syslog addr=[%s], program_name=[%s]", syslogAddr, syslogProgramName)
	logrusSysLogHook, err := logrus_syslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, syslogProgramName)
	if err != nil {
		log.Fatalf("Failed to add syslog logrus hook - %s", err)
	}
	log.AddHook(logrusSysLogHook)
}

func setupFileLogging(logFile string) {
	log.Printf("Logging to file=[%s]", logFile)
	logrusFileHook := lfshook.NewHook(lfshook.PathMap{
		log.InfoLevel: logFile, log.WarnLevel: logFile, log.ErrorLevel: logFile, log.FatalLevel: logFile, log.PanicLevel: logFile,
	})
	log.AddHook(logrusFileHook)
}

func main() {
	app := cli.NewApp()
	app.Name = "sshoney"
	app.Usage = "SSH honeypot"
	app.Version = "0.1.0"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "port",
			Usage:  "port to listen on",
			Value:  "2222",
			EnvVar: "PORT",
		},
		cli.StringFlag{
			Name:   "host-key",
			Usage:  "SSH private host key",
			Value:  "host.key",
			EnvVar: "HOST_KEY",
		},
		cli.BoolFlag{Name: "log-to-syslog", Usage: "log to syslog"},
		cli.StringFlag{
			Name:   "syslog-addr",
			Usage:  "host:port of the syslog server",
			Value:  "localhost:514",
			EnvVar: "SYSLOG_ADDR",
		},
		cli.StringFlag{
			Name:   "syslog-program-name",
			Usage:  "syslog program name to use",
			Value:  "sshoney",
			EnvVar: "SYSLOG_PROGRAM_NAME",
		},
		cli.StringFlag{
			Name:   "log-file",
			Usage:  "path to logfile",
			EnvVar: "LOG_FILE",
		},
	}

	app.Action = func(c *cli.Context) {
		setupLogging(c.Bool("log-to-syslog"), c.String("syslog-addr"), c.String("syslog-program-name"), c.String("log-file"))
		sshoney.Listen(c.String("port"), c.String("host-key"))
	}

	app.Run(os.Args)
}
