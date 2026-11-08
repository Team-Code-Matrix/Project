import type { WorkerStatus, WorkerPoolId } from '../types/backend';

export type ScanEventType =
  | 'WORKER_STARTED'
  | 'WORKER_PROGRESS'
  | 'WORKER_COMPLETED'
  | 'WORKER_FAILED'
  | 'SCAN_COMPLETED';

export interface ScanProgressEvent {
  scanId: string;
  eventType: ScanEventType;
  workerId: WorkerPoolId;
  workerName: string;
  status: WorkerStatus['status'];
  progressPercentage?: number;
  snippet?: string;
  timestamp: string;
}

export type ScanEventCallback = (event: ScanProgressEvent) => void;

import { API_BASE_URL, WS_BASE_URL } from '../config/api';
const DEFAULT_WS_URL = WS_BASE_URL;

export class ScanWebSocketService {
  private subscribers: Map<string, Set<ScanEventCallback>> = new Map();
  private threatSubscribers: Set<(threat: any) => void> = new Set();
  private activeSockets: Map<string, WebSocket> = new Map();

  /**
   * Subscribes to live progress events for a specific scanId.
   */
  subscribe(scanId: string, callback: ScanEventCallback): () => void {
    if (!this.subscribers.has(scanId)) {
      this.subscribers.set(scanId, new Set());
    }
    this.subscribers.get(scanId)!.add(callback);

    // Ensure a live WebSocket connection is open for this scanId
    this.ensureSocketConnection(scanId);

    return () => {
      const set = this.subscribers.get(scanId);
      if (set) {
        set.delete(callback);
        if (set.size === 0) {
          this.subscribers.delete(scanId);
          this.closeSocket(scanId);
        }
      }
    };
  }

  /**
   * Subscribes to real-time global cyber threat IOC ingestion events.
   */
  subscribeToGlobalThreatFeed(callback: (threat: any) => void): () => void {
    this.threatSubscribers.add(callback);
    this.ensureSocketConnection('global-feed');

    return () => {
      this.threatSubscribers.delete(callback);
      if (this.threatSubscribers.size === 0) {
        this.closeSocket('global-feed');
      }
    };
  }

  /**
   * Connects to the genuine backend WebSocket endpoint for a scan or global feed.
   */
  private ensureSocketConnection(scanId: string): void {
    if (this.activeSockets.has(scanId)) return;

    try {
      const wsUrl = `${DEFAULT_WS_URL}/ws/scans/${scanId}`;
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload && payload.eventType === 'THREAT_INGESTED') {
            this.threatSubscribers.forEach((cb) => {
              try {
                cb(payload.threat);
              } catch {
                // Ignore subscriber error
              }
            });
          } else if (payload) {
            this.dispatchEvent(payload as ScanProgressEvent);
          }
        } catch {
          // Ignore invalid frames
        }
      };

      ws.onclose = () => {
        this.activeSockets.delete(scanId);
      };

      ws.onerror = () => {
        this.activeSockets.delete(scanId);
      };

      this.activeSockets.set(scanId, ws);
    } catch {
      // WebSocket connection failed (graceful degradation)
    }
  }

  private closeSocket(scanId: string): void {
    const ws = this.activeSockets.get(scanId);
    if (ws) {
      try {
        ws.close();
      } catch {
        // Fallback
      }
      this.activeSockets.delete(scanId);
    }
  }

  /**
   * Dispatches events to registered listeners.
   */
  dispatchEvent(event: ScanProgressEvent): void {
    const set = this.subscribers.get(event.scanId);
    if (set) {
      set.forEach((cb) => cb(event));
    }
    const defaultSet = this.subscribers.get('default');
    if (defaultSet) {
      defaultSet.forEach((cb) => cb(event));
    }
  }

  /**
   * Backward-compatible alias for unit tests.
   */
  dispatchMockEvent(event: ScanProgressEvent): void {
    this.dispatchEvent(event);
  }

  disconnectAll(): void {
    this.activeSockets.forEach((ws) => {
      try {
        ws.close();
      } catch {
        // Fallback
      }
    });
    this.activeSockets.clear();
    this.subscribers.clear();
  }
}

export const scanWebSocketService = new ScanWebSocketService();
