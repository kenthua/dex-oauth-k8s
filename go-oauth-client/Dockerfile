FROM alpine

COPY ./ca.crt /usr/local/share/ca-certificates/ca.crt

RUN apk --update upgrade && \
    apk add curl ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/cache/apk/*

COPY gopath/bin/go-oauth-client /go-oauth-client

EXPOSE 3000

ENTRYPOINT ["/go-oauth-client"]

