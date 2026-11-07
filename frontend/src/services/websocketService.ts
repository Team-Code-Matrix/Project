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

export class ScanWebSocketService {
  private subscribers: Map<string, Set<ScanEventCallback>> = new Map();
  private ws: WebSocket | null = null;
  private isConnected = false;

  /**
   * Subscribes to live progress events for a specific scanId.
   */
  subscribe(scanId: string, callback: ScanEventCallback): () => void {
    if (!this.subscribers.has(scanId)) {
      this.subscribers.set(scanId, new Set());
    }
    this.subscribers.get(scanId)!.add(callback);

    // If real backend WebSocket is active, send subscription frame
    if (this.ws && this.isConnected) {
      this.ws.send(JSON.stringify({ action: 'SUBSCRIBE', scanId }));
    }

    return () => {
      const set = this.subscribers.get(scanId);
      if (set) {
        set.delete(callback);
        if (set.size === 0) {
          this.subscribers.delete(scanId);
        }
      }
    };
  }

  /**
   * Dispatches events to registered listeners (used by both mock orchestration and live WS).
   */
  dispatchMockEvent(event: ScanProgressEvent): void {
    const set = this.subscribers.get(event.scanId);
    if (set) {
      set.forEach((cb) => cb(event));
    }
  }

  /**
   * Connects to a live WebSocket server when configured.
   */
  connectLive(url: string): void {
    try {
      this.ws = new WebSocket(url);
      this.ws.onopen = () => {
        this.isConnected = true;
      };
      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as ScanProgressEvent;
          if (payload?.scanId) {
            this.dispatchMockEvent(payload);
          }
        } catch {
          // Ignore malformed payloads
        }
      };
      this.ws.onclose = () => {
        this.isConnected = false;
      };
    } catch {
      this.isConnected = false;
    }
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
  }
}

export const scanWebSocketService = new ScanWebSocketService();

