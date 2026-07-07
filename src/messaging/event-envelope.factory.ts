import { Injectable } from '@nestjs/common';
import { trace } from './trace-context.js';

export interface EventEnvelope {
  event_id: string;
  event_type: string;
  schema_version: number;
  occurred_at: string;
  tenant_id: string;
  correlation_id: string;
  causation_id: string | null;
  idempotency_key: string | null;
  payload: Record<string, unknown>;
}

/** Factory for the platform event envelope (contracts/events/README.md). */
@Injectable()
export class EventEnvelopeFactory {
  build(
    eventId: string,
    topic: string,
    payload: Record<string, unknown>,
    opts?: { causationId?: string; idempotencyKey?: string; occurredAt?: Date },
  ): EventEnvelope {
    return {
      event_id: eventId,
      event_type: topic,
      schema_version: 1,
      occurred_at: (opts?.occurredAt ?? new Date()).toISOString(),
      tenant_id: 'peikon',
      correlation_id: trace.currentTraceId(),
      causation_id: opts?.causationId ?? null,
      idempotency_key: opts?.idempotencyKey ?? null,
      payload,
    };
  }
}
