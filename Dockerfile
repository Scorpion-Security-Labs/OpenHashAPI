# Dockerfile for OpenHashAPI

# Build Binary then transfer it across layers
FROM golang:1.22-alpine as build-env
RUN mkdir src/app
WORKDIR /src/app
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./go.mod .
COPY ./go.sum .
RUN cd ./cmd && go build .

# Deployment layer
FROM alpine:latest

# Configuration
ENV GIN_MODE=release

# Location of your config file
ENV CONF_FILE=./config/config.json
COPY ${CONF_FILE} /etc/config.json

# Copy over static files
COPY /static /var/www/OpenHashAPI/static
COPY /templates /var/www/OpenHashAPI/templates

# Make secret material
# NOTE: Self-signed cert 
RUN apk update; apk add --no-cache openssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout server.key -out server.crt -subj '/CN=www.OpenHashAPI.com' && \
    chmod 604 server.key && chmod 604 server.crt && \
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096 && \
    openssl rsa -in private_key.pem -pubout -out public_key.pem && \
    chmod 604 private_key.pem && chmod 604 public_key.pem && \
    chmod 604 /etc/config.json;

# Install packages and create app user
RUN addgroup --gid 10001 --system nonroot \
    && adduser  --uid 10000 --system --ingroup nonroot --home /home/nonroot nonroot; \
    apk update; apk add --no-cache tini bind-tools; \
    mkdir -p /var/www/OpenHashAPI && chown nonroot:nonroot /var/www/OpenHashAPI \
    && mkdir -p /var/www/OpenHashAPI/logs && chown nonroot:nonroot /var/www/OpenHashAPI/logs \
    && mkdir -p /var/www/OpenHashAPI/lists && chown nonroot:nonroot /var/www/OpenHashAPI/lists \
    && chown nonroot:nonroot /var/www/OpenHashAPI/static && chown nonroot:nonroot /var/www/OpenHashAPI/static/* \
    && chown nonroot:nonroot /var/www/OpenHashAPI/templates && chown nonroot:nonroot /var/www/OpenHashAPI/templates/*;

# Copy app over and set entrypoint
COPY --from=build-env /src/app/cmd/cmd /sbin/ohaserver
ENTRYPOINT ["/sbin/tini", "--", "/sbin/ohaserver"]

# Use the non-root user to run our application
USER nonroot
