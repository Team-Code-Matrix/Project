package ws

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gofiber/websocket/v2"
	"github.com/trustshield/backend/shared/libs/go/models"
)

type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]map[*websocket.Conn]bool
}

func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[string]map[*websocket.Conn]bool),
	}
}

// Register adds a new client connection for a specific scanID
func (h *Hub) Register(scanID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.subscribers[scanID]; !ok {
		h.subscribers[scanID] = make(map[*websocket.Conn]bool)
	}
	h.subscribers[scanID][conn] = true
	log.Printf("[WS Hub] Client registered for scanId: %s", scanID)
}

// Unregister removes a connection for a specific scanID
func (h *Hub) Unregister(scanID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conns, ok := h.subscribers[scanID]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(h.subscribers, scanID)
		}
	}
	_ = conn.Close()
	log.Printf("[WS Hub] Client unregistered for scanId: %s", scanID)
}

// Broadcast dispatches a ScanProgressEvent to all connected clients listening to scanID
func (h *Hub) Broadcast(event *models.ScanProgressEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	conns, ok := h.subscribers[event.ScanID]
	if !ok || len(conns) == 0 {
		return
	}

	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("[WS Hub] Failed to marshal event: %v", err)
		return
	}

	for conn := range conns {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			log.Printf("[WS Hub] Error sending message to client: %v", err)
			_ = conn.Close()
			delete(conns, conn)
		}
	}
}

