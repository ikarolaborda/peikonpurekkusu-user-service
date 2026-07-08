import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import { trace } from './trace-context.js';
import type { EventEnvelope } from './event-envelope.factory.js';

/**
 * Producer emitting the Confluent wire format (magic byte 0x00 + big-endian
 * int32 schema id + JSON payload) against the Apicurio ccompat endpoint.
 *
 * The framing is done by hand: schema ids come from
 * GET /subjects/<topic>-value/versions/latest (cached per topic). The
 * @confluentinc/schemaregistry serializer is NOT used — its useLatestVersion
 * path resolves through the Confluent "schema associations" API, which
 * Apicurio's ccompat surface does not implement (404s). Schemas themselves
 * are registered by the schemas-init job from contracts/events/.
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KafkaProducerService.name);
  private readonly kafka: KafkaJS.Kafka;
  private producer: KafkaJS.Producer;
  private readonly registryUrl: string;
  private readonly schemaIds = new Map<string, number>();
  private connected = false;
  private consecutiveTimeouts = 0;
  private reconnecting = false;

  constructor(config: ConfigService) {
    this.kafka = new KafkaJS.Kafka({
      kafkaJS: {
        clientId: 'user-service',
        brokers: config.getOrThrow<string>('KAFKA_BOOTSTRAP_SERVERS').split(','),
      },
    });
    this.producer = this.newProducer();
    this.registryUrl = config.getOrThrow<string>('SCHEMA_REGISTRY_URL').replace(/\/$/, '');
  }

  private newProducer(): KafkaJS.Producer {
    return this.kafka.producer({ kafkaJS: { acks: -1, idempotent: true } });
  }

  async onModuleInit(): Promise<void> {
    await this.producer.connect();
    this.connected = true;
    this.logger.log('kafka producer connected');
  }

  async onModuleDestroy(): Promise<void> {
    if (this.connected) await this.producer.disconnect();
  }

  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Self-heal a stale producer. librdkafka usually reconnects on its own, but
   * a broker restart can leave the idempotent producer unable to re-acquire
   * its PID — every send then times out. After a few consecutive timeouts we
   * recreate the producer so the outbox relay can drain instead of wedging.
   */
  private async recoverIfStale(): Promise<void> {
    if (this.reconnecting || this.consecutiveTimeouts < 3) return;
    this.reconnecting = true;
    try {
      this.logger.warn('recreating kafka producer after repeated send timeouts');
      try {
        await this.producer.disconnect();
      } catch {
        /* best effort */
      }
      this.producer = this.newProducer();
      await this.producer.connect();
      this.consecutiveTimeouts = 0;
      this.logger.log('kafka producer reconnected');
    } catch (err) {
      this.logger.error(`producer reconnect failed: ${(err as Error).message}`);
    } finally {
      this.reconnecting = false;
    }
  }

  async publish(topic: string, key: string, envelope: EventEnvelope): Promise<void> {
    const value = this.frame(await this.schemaId(topic), envelope);
    const send = this.producer.send({
      topic,
      messages: [
        {
          key,
          value,
          headers: { traceparent: trace.currentTraceparent() },
        },
      ],
    });
    // A broker outage can leave send() pending indefinitely (observed with
    // idempotent-PID acquisition during a Kafka restart), which would wedge
    // the outbox relay's drain flag forever. Fail loudly; the relay retries.
    const timeout = new Promise<never>((_, reject) => {
      const t = setTimeout(() => reject(new Error(`kafka send timeout (${topic})`)), 15_000);
      t.unref();
    });
    try {
      await Promise.race([send, timeout]);
      this.consecutiveTimeouts = 0;
    } catch (err) {
      if ((err as Error).message.includes('send timeout')) {
        this.consecutiveTimeouts += 1;
        void this.recoverIfStale();
      }
      throw err;
    }
  }

  private frame(schemaId: number, envelope: EventEnvelope): Buffer {
    const payload = Buffer.from(JSON.stringify(envelope), 'utf8');
    const header = Buffer.alloc(5);
    header.writeUInt8(0, 0);
    header.writeInt32BE(schemaId, 1);
    return Buffer.concat([header, payload]);
  }

  private async schemaId(topic: string): Promise<number> {
    const cached = this.schemaIds.get(topic);
    if (cached !== undefined) return cached;
    const res = await fetch(`${this.registryUrl}/subjects/${topic}-value/versions/latest`);
    if (!res.ok) {
      throw new Error(`schema lookup for ${topic}-value failed: HTTP ${res.status}`);
    }
    const { id } = (await res.json()) as { id: number };
    this.schemaIds.set(topic, id);
    return id;
  }
}
