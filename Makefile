.PHONY: all clean
.DEFAULT_GOAL := all

PORT ?= 2222
DEBUG ?= false

deps:
	go get ./...

all: deps
	go build -o ssh_h0neyp0t

clean:
	rm -f ssh_h0neyp0tn

run:
	DEBUG="$(DEBUG)" PORT="$(PORT)" go run server.go

gen_ssh_key:
	ssh-keygen -f ./host.key -N ''

show_iptables_rule:
	@echo "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port $(PORT)"
