import { defineEntity, type InferEntity } from '@mikro-orm/core';
import { v7 as uuidv7 } from 'uuid';

/**
 * Transactional outbox row — written in the same Unit-of-Work transaction as
 * the state change it announces. Column names are Debezium Outbox Event
 * Router-compatible so the polling relay can be swapped for CDC untouched.
 * id is uuidv7 → time-ordered, doubles as the envelope event_id / dedup key.
 */
export const OutboxEvent = defineEntity({
  name: 'OutboxEvent',
  tableName: 'outbox',
  properties: (p) => ({
    id: p.uuid().primary().onCreate(() => uuidv7()),
    aggregatetype: p.string(),
    aggregateid: p.string(),
    type: p.string(),
    payload: p.json().$type<Record<string, unknown>>(),
    createdAt: p.datetime().onCreate(() => new Date()),
    processedAt: p.datetime().nullable(),
  }),
});

export type OutboxEventEntity = InferEntity<typeof OutboxEvent>;
