# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/a07-auth-failures .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/a07-auth-failures /app/a07-auth-failures
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/a07-auth-failures"]
