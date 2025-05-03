FROM scratch

ARG TARGETPLATFORM

WORKDIR /app

ADD release/${TARGETPLATFORM}.tar /app/

ENTRYPOINT ["/app/dcdn"]
