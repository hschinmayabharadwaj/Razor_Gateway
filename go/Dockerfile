FROM golang:1.23-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o server ./cmd/stream-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /app/server /app/server
COPY data /app/data
EXPOSE 8090
CMD ["/app/server"]
