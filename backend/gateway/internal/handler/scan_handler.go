package handler

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/trustshield/backend/gateway/internal/security"
	"github.com/trustshield/backend/gateway/internal/service/deepscan"
	"github.com/trustshield/backend/gateway/internal/service/fastpath"
	"github.com/trustshield/backend/gateway/internal/transport/ws"
)

type ScanHandler struct {
	fastPath     *fastpath.FastPathEvaluator
	orchestrator *deepscan.Orchestrator
	wsHub        *ws.Hub
}

func NewScanHandler(fp *fastpath.FastPathEvaluator, orc *deepscan.Orchestrator, hub *ws.Hub) *ScanHandler {
	return &ScanHandler{
		fastPath:     fp,
		orchestrator: orc,
		wsHub:        hub,
	}
}

type ScanRequest struct {
	URL       string `json:"url"`
	IsPrivate bool   `json:"is_private"`
}

// FastPathScan evaluates sub-150ms synchronous checks against Bloom filters and IDN/Punycode.
// POST /api/v1/scan/fast-path
func (h *ScanHandler) FastPathScan(c *fiber.Ctx) error {
	var req ScanRequest
	if err := c.BodyParser(&req); err != nil || req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing or invalid 'url' in request body",
		})
	}

	canon, err := security.CanonicalizeURL(req.URL)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	verdict, err := h.fastPath.Evaluate(ctx, canon)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Fast-path evaluation failure: " + err.Error(),
		})
	}

	return c.JSON(verdict)
}

// InitiateDeepScan initiates asynchronous multi-pillar deep analysis.
// POST /api/v1/scan
func (h *ScanHandler) InitiateDeepScan(c *fiber.Ctx) error {
	var req ScanRequest
	if err := c.BodyParser(&req); err != nil || req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing or invalid 'url' in request body",
		})
	}

	canon, err := security.CanonicalizeURL(req.URL)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	scanID, err := h.orchestrator.InitiateScan(context.Background(), canon, req.IsPrivate)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initiate deep scan: " + err.Error(),
		})
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"scanId":       scanID,
		"status":       "QUEUED",
		"canonicalUrl": canon.NormalizedURL,
		"wsUrl":        "/ws/scans/" + scanID,
		"checkedAt":    time.Now().UTC().Format(time.RFC3339),
	})
}

// GetScanReport returns the full extended report for a given scanID.
// GET /api/v1/scan/:id
func (h *ScanHandler) GetScanReport(c *fiber.Ctx) error {
	scanID := c.Params("id")
	if scanID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing scan ID parameter",
		})
	}

	report, found := h.orchestrator.GetReport(scanID)
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Scan report not found for id: " + scanID,
		})
	}

	return c.JSON(report)
}

// GetScanHistory returns the recent scan history list.
// GET /api/v1/scan/history
func (h *ScanHandler) GetScanHistory(c *fiber.Ctx) error {
	history := h.orchestrator.GetHistory()
	return c.JSON(history)
}

// WebSocketUpgrade handles WebSocket connections for live scan streaming.
// GET /ws/scans/:id
func (h *ScanHandler) WebSocketUpgrade() fiber.Handler {
	return websocket.New(func(c *websocket.Conn) {
		scanID := c.Params("id")
		if scanID == "" {
			_ = c.Close()
			return
		}

		h.wsHub.Register(scanID, c)
		defer h.wsHub.Unregister(scanID, c)

		// Listen for client incoming frames (e.g. SUBSCRIBE or PING)
		for {
			messageType, message, err := c.ReadMessage()
			if err != nil {
				break
			}
			if messageType == websocket.TextMessage {
				log.Printf("[WS Client %s] Message: %s", scanID, string(message))
			}
		}
	})
}

