package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port                string
	Environment         string
	CorsAllowedOrigins  string
	DatabaseURL         string
	RedisHost           string
	RedisPort           string
	RedisPassword       string
	KafkaBrokers        string
	TopicScanTasks      string
	TopicScanResults    string
	TopicScanTelemetry  string
	TopicDLQ            string
	MaxBodyBytes        int64
	MaxRedirectHops     int
	MaxCertChainBytes   int64
	DetonationTimeoutSec int
}

func LoadConfig() *Config {
	port := getEnv("PORT", "8000")
	env := getEnv("ENVIRONMENT", "development")
	cors := getEnv("CORS_ALLOWED_ORIGINS", "*")
	dbURL := getEnv("DATABASE_URL", "postgresql://postgres:postgres_secure_pass@localhost:5432/trustshield?sslmode=disable")
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisPass := getEnv("REDIS_PASSWORD", "redis_secure_pass")
	kafkaBrokers := getEnv("KAFKA_BROKERS", "localhost:9094")

	maxBody, _ := strconv.ParseInt(getEnv("SCANNER_MAX_BODY_BYTES", "10485760"), 10, 64)
	maxHops, _ := strconv.Atoi(getEnv("SCANNER_MAX_REDIRECT_HOPS", "5"))
	maxCert, _ := strconv.ParseInt(getEnv("SCANNER_MAX_CERT_CHAIN_BYTES", "65536"), 10, 64)
	timeoutSec, _ := strconv.Atoi(getEnv("SCANNER_DETONATION_TIMEOUT_SEC", "15"))

	return &Config{
		Port:                 port,
		Environment:          env,
		CorsAllowedOrigins:   cors,
		DatabaseURL:          dbURL,
		RedisHost:            redisHost,
		RedisPort:            redisPort,
		RedisPassword:        redisPass,
		KafkaBrokers:         kafkaBrokers,
		TopicScanTasks:       getEnv("KAFKA_TOPIC_SCAN_TASKS", "trustshield.scan.tasks"),
		TopicScanResults:     getEnv("KAFKA_TOPIC_SCAN_RESULTS", "trustshield.scan.results"),
		TopicScanTelemetry:   getEnv("KAFKA_TOPIC_SCAN_TELEMETRY", "trustshield.scan.telemetry"),
		TopicDLQ:             getEnv("KAFKA_TOPIC_DEAD_LETTER", "trustshield.scan.dlq"),
		MaxBodyBytes:         maxBody,
		MaxRedirectHops:      maxHops,
		MaxCertChainBytes:    maxCert,
		DetonationTimeoutSec: timeoutSec,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

