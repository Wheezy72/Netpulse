import { onBeforeUnmount, ref } from "vue";

export interface UseWebSocketOptions {
  /** Called with each parsed JSON payload. */
  onMessage: (payload: unknown) => void;
  /** Called when the socket opens (reconnected included). */
  onOpen?: () => void;
  /** Called when a permanent close (not a reconnect) occurs, e.g. disabled=true. */
  onClosed?: () => void;
  /** Initial back-off delay in ms (doubles each attempt, capped at maxDelay). */
  initialDelay?: number;
  /** Maximum back-off delay in ms. */
  maxDelay?: number;
}

/**
 * Composable that manages a WebSocket connection with automatic exponential-
 * backoff reconnection. The socket is torn down in onBeforeUnmount.
 *
 * Usage:
 *   const { connect, disconnect, connected } = useWebSocket({ onMessage });
 *   connect("wss://host/api/ws/metrics?token=…");
 */
export function useWebSocket(options: UseWebSocketOptions) {
  const {
    onMessage,
    onOpen,
    onClosed,
    initialDelay = 1_000,
    maxDelay = 30_000,
  } = options;

  const connected = ref(false);

  let socket: WebSocket | null = null;
  let currentUrl = "";
  let retryDelay = initialDelay;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let enabled = false;

  function clearRetryTimer(): void {
    if (retryTimer !== null) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
  }

  function openSocket(): void {
    if (!enabled || !currentUrl) return;

    socket = new WebSocket(currentUrl);

    socket.onopen = () => {
      connected.value = true;
      retryDelay = initialDelay; // reset back-off on successful connection
      onOpen?.();
    };

    socket.onmessage = (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data as string);
        onMessage(payload);
      } catch {
        // ignore malformed frames
      }
    };

    socket.onerror = () => {
      socket?.close();
    };

    socket.onclose = () => {
      connected.value = false;
      socket = null;

      if (!enabled) {
        onClosed?.();
        return;
      }

      // Schedule reconnect with exponential back-off.
      retryTimer = setTimeout(() => {
        retryDelay = Math.min(retryDelay * 2, maxDelay);
        openSocket();
      }, retryDelay);
    };
  }

  function connect(url: string): void {
    if (socket) disconnect();
    currentUrl = url;
    enabled = true;
    retryDelay = initialDelay;
    openSocket();
  }

  function disconnect(): void {
    enabled = false;
    clearRetryTimer();
    if (socket) {
      socket.close();
      socket = null;
    }
    connected.value = false;
  }

  onBeforeUnmount(disconnect);

  return { connect, disconnect, connected };
}
