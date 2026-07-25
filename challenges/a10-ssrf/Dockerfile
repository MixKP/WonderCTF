# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/a10-ssrf .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/a10-ssrf /app/a10-ssrf
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/a10-ssrf"]
