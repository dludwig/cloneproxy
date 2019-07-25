BINARY=cloneproxy

VERSION=4.1.0
MINVERSION=`date -u +%Y%m%d.%H%M%S`
BUILD=$(shell git rev-parse HEAD)

LDFLAGS=-ldflags "-X main.VERSION=${VERSION} -X main.minversion=${MINVERSION} -X main.build=${BUILD}"

install:
	go get ./...

release:
	env GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o build/${BINARY} ${BINARY}.go

clean:
	if [ -f build/${BINARY} ] ; then rm build/${BINARY} ; fi