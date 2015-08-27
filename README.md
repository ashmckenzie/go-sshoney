SSHoney
=======

SSHoney is an SSH honeypot designed purely to log the SSH connections on a given port.  It
does not go any further than that.

How?
----

SSHoney works by listening on a non-privileged port (2222) by default and pretends to be an SSH
server.  When an SSH client connects, SSHoney simply logs the connection details to syslog and
to `/var/log/sshoney.log`.

Basic setup
-----------

Install the binary:

```shell
go get -u github.com/ashmckenzie/sshoney`
```

Ensure `${GOPATH}/bin` is in your `${PATH}` (so you can run `sshoney` from any directory):

```shell
export PATH:${PATH}:${GOPATH}/bin
```

Run it and you will be asked to generate a `host.key`:

```shell
$ cd /tmp
$ sshoney
time="2015-08-28T08:48:35+10:00" level=fatal msg="Failed to load private key ./host.key.  Run make gen_ssh_key"
```

That's cool, let's generate one!:

```shell
$ make -f ${GOPATH}/src/github.com/ashmckenzie/sshoney/Makefile gen_ssh_key
ssh-keygen -f ./host.key -N ''
Generating public/private rsa key pair.
Your identification has been saved in ./host.key.
Your public key has been saved in ./host.key.pub.
The key fingerprint is:
SHA256:5QH4ForyXNVRuUPPuKtyg2//swPLtw4c3DyS0idTpUk ash@ashmckenzie
The key's randomart image is:
+---[RSA 2048]----+
|       ....o..E .|
|      . o.. o. + |
|     . + .o. =+  |
|  . . o oo ++=o  |
|   + . .S o Oo=  |
|    o      oo* . |
|         . .o+   |
|        o + +.+  |
|         =o+.+== |
+----[SHA256]-----+
```

Let's run it again:

```shell
$ sshoney
time="2015-08-28T08:59:58+10:00" level=info msg="listening on 2222"
```

SSHoney is now logging to stdout and `/var/log/sshoney`.  It's also listening on port 2222 which is not the standard SSH port (22 is).  This is deliberately setup this way to ensure:

1. You are not locked out of a remote server by default
2. The SSHoney service is not running as root

Proceed to the [Running live](#running-live) section for the best way to run this on a real server.

Running live
------------

SSHoney listens on port 2222 by default.  This can be changed by prefixing the `sshoney` command with `PORT=<PORT>`:

e.g.

```shell
$ PORT=2223 sshoney
time="2015-08-28T09:11:13+10:00" level=info msg="listening on 2223"
```

Once you have SSHoney running (ideally as the least privileged user, e.g. `nobody`) it's time to setup an IPTables rule to redirect the traffic.  The easiest way to do this is to run the provided helper in the `Makefile`:

```shell
$ make -f ${GOPATH}/src/github.com/ashmckenzie/sshoney/Makefile show_iptables_rule
==========================================================================================
WARNING: Please, please be very careful when adding this rule you don't lock yourself out!
==========================================================================================

sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2222
```

This can again, be customised by prefixing the `make` command with `PORT=<PORT>`:

$ PORT=2223 make -f ${GOPATH}/src/github.com/ashmckenzie/sshoney/Makefile show_iptables_rule

WARNING: Please, please be very careful when adding this rule you don't lock yourself out!

sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2223
```

Log format
----------

Logging is handled using the very awesome https://github.com/Sirupsen/logrus library.

General format:

`time="<TIMESTAMP>" level="<LEVEL>" msg="<MSG>"`

e.g.

`time="2015-08-28T08:59:58+10:00" level=info msg="listening on 2222"`

Specific format for SSH connection attempts:

`time="<TIMESTAMP>" level="<LEVEL>" msg="new SSH connection from <IP>:<RANDOM_PORT> (<SSH_CLIENT_VERSION>)"`

e.g.

`time="2015-08-28T09:01:23+10:00" level=info msg="new SSH connection from 127.0.0.1:56429 (SSH-2.0-OpenSSH_6.2)"`

Logstash
--------

Logstash is awesome so I included a config and pattern helper in this repo to make it easier to ingest SSHoney log entries into Logstash!

Included is `logstash/filter.conf` that defines a filter and `logstash/patterns/sshoney.pattern` to make parsing easier.
