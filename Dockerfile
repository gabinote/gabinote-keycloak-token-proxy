# ----------------------------
# Build Stage
# ----------------------------
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 시스템 패키지 설치
RUN apk add --no-cache git ca-certificates tzdata

# Go 모듈 캐싱
COPY go.mod go.sum ./
RUN go mod download

# 소스 복사
COPY . .

# 애플리케이션 빌드
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o keycloak-token-proxy cmd/main.go

# ----------------------------
# Final Stage
# ----------------------------
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/keycloak-token-proxy .
COPY --from=builder /app/config/config.yaml ./config/

RUN chown appuser:appgroup keycloak-token-proxy config/config.yaml

# 사용자 전환
USER appuser

# 환경 변수
ENV PORT=8080
EXPOSE ${PORT}

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# 실행
CMD ["./keycloak-token-proxy"]
