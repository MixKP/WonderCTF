# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/a01-broken-access-control .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/a01-broken-access-control /app/a01-broken-access-control
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/a01-broken-access-control"]
