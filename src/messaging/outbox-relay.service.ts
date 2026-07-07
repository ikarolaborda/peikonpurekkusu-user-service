import { MikroORM } from '@mikro-orm/postgresql';
import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { EventEnvelopeFactory } from './event-envelope.factory.js';
import { KafkaProducerService } from './kafka-producer.service.js';

const POLL_INTERVAL_MS = 500;
const BATCH_SIZE = 50;

/**
 * Polling outbox relay. `FOR UPDATE SKIP LOCKED` lets replicas compete safely;
 * delivery is at-least-once (consumers dedupe on event_id = outbox row id).
 * Rows are marked processed rather than deleted so the table stays
 * Debezium-swappable (CDC reads inserts from the WAL either way).
 */
@Injectable()
export class OutboxRelayService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelayService.name);
  private timer?: NodeJS.Timeout;
  private draining = false;

  constructor(
    private readonly orm: MikroORM,
    private readonly producer: KafkaProducerService,
    private readonly envelopes: EventEnvelopeFactory,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => void this.drainOnce(), POLL_INTERVAL_MS);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async drainOnce(): Promise<number> {
    if (this.draining || !this.producer.isConnected()) return 0;
    this.draining = true;
    try {
      const em = this.orm.em.fork();
      let published = 0;
      await em.transactional(async (tem) => {
        const rows: Array<{
          id: string;
          aggregateid: string;
          type: string;
          payload: Record<string, unknown>;
          created_at: string;
        }> = await tem.getConnection().execute(
          `select id, aggregateid, type, payload, created_at from outbox
           where processed_at is null
           order by id
           limit ?
           for update skip locked`,
          [BATCH_SIZE],
        );
        for (const row of rows) {
          const envelope = this.envelopes.build(row.id, row.type, row.payload, {
            occurredAt: new Date(row.created_at),
          });
          await this.producer.publish(row.type, row.aggregateid, envelope);
          published += 1;
        }
        if (rows.length > 0) {
          await tem
            .getConnection()
            .execute(`update outbox set processed_at = now() where id in (?)`, [rows.map((r) => r.id)]);
        }
      });
      return published;
    } catch (err) {
      this.logger.error(`outbox drain failed (will retry): ${(err as Error).message}`);
      return 0;
    } finally {
      this.draining = false;
    }
  }
}
