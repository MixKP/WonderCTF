# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/a09-logging-failures .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/a09-logging-failures /app/a09-logging-failures
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/a09-logging-failures"]
