FROM golang:1.23.4 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download 
RUN CGO_ENABLED=0 GOOS=linux go build -o /gitsync

FROM bitnami/git:2.39.1-debian-11-r6
ARG ROLE_ID
ARG SECRET_ID
ARG DAG_PATH
ARG VAULT_ADDR
ENV ROLE_ID=${ROLE_ID}
ENV SECRET_ID=${SECRET_ID}
ENV DAG_PATH=${DAG_PATH}
ENV VAULT_ADDR=${VAULT_ADDR}

WORKDIR /app
RUN chown -R 1000:3000 /app
USER 1000:3000
COPY --from=builder /gitsync /gitsync
CMD ["/gitsync", "pull"]