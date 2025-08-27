FROM golang:1.24 as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go generate ./pkg/cmd/server.go
RUN go build -o ./scanoss-vulnerabilities ./cmd/server

FROM debian:buster-slim

WORKDIR /app
 
COPY --from=build /app/scanoss-vulnerabilities /app/scanoss-vulnerabilities

EXPOSE 50051

ENTRYPOINT ["./scanoss-vulnerabilities"]
#CMD ["--help"]
