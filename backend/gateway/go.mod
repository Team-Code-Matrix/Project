module github.com/trustshield/backend/gateway

go 1.22

require (
	github.com/gofiber/fiber/v2 v2.52.4
	github.com/gofiber/websocket/v2 v2.2.1
	github.com/google/uuid v1.6.0
	github.com/redis/go-redis/v9 v9.5.1
	github.com/segmentio/kafka-go v0.4.47
	golang.org/x/net v0.25.0
	google.golang.org/protobuf v1.34.1
	github.com/trustshield/backend/shared/libs/go/models v0.0.0
)

replace github.com/trustshield/backend/shared/libs/go/models => ../shared/libs/go/models
