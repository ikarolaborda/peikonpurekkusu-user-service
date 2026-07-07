import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';

interface TraceState {
  traceId: string;
}

const storage = new AsyncLocalStorage<TraceState>();

/**
 * Minimal W3C trace-context carrier. Middleware seeds it from an incoming
 * `traceparent` header (or mints a new trace id); producers stamp it into the
 * event envelope + Kafka headers so a payment can be followed across services
 * even before the full OTel SDK is enabled (OTEL_SDK_DISABLED=true in dev).
 */
export const trace = {
  run<T>(traceparent: string | undefined, fn: () => T): T {
    const traceId = parseTraceparent(traceparent) ?? randomBytes(16).toString('hex');
    return storage.run({ traceId }, fn);
  },
  currentTraceId(): string {
    return storage.getStore()?.traceId ?? randomBytes(16).toString('hex');
  },
  currentTraceparent(): string {
    return `00-${trace.currentTraceId()}-${randomBytes(8).toString('hex')}-01`;
  },
};

function parseTraceparent(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/.exec(header.trim());
  return m ? m[1] : null;
}
