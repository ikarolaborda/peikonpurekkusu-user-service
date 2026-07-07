import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import {
  JsonSerializer,
  SchemaRegistryClient,
  SerdeType,
} from '@confluentinc/schemaregistry';
import { trace } from './trace-context.js';
import type { EventEnvelope } from './event-envelope.factory.js';

/**
 * Confluent-wire-format producer against the Apicurio ccompat endpoint.
 * Subjects follow TopicNameStrategy ("<topic>-value"); schemas are
 * pre-registered by the schemas-init job, so we resolve the latest version
 * instead of auto-registering.
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KafkaProducerService.name);
  private producer: KafkaJS.Producer;
  private serializer: JsonSerializer;
  private connected = false;

  constructor(config: ConfigService) {
    const kafka = new KafkaJS.Kafka({
      kafkaJS: {
        clientId: 'user-service',
        brokers: config.getOrThrow<string>('KAFKA_BOOTSTRAP_SERVERS').split(','),
      },
    });
    this.producer = kafka.producer({
      kafkaJS: { acks: -1, idempotent: true },
    });
    const registry = new SchemaRegistryClient({
      baseURLs: [config.getOrThrow<string>('SCHEMA_REGISTRY_URL')],
    });
    this.serializer = new JsonSerializer(registry, SerdeType.VALUE, {
      useLatestVersion: true,
      autoRegisterSchemas: false,
    });
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

  async publish(topic: string, key: string, envelope: EventEnvelope): Promise<void> {
    const value = await this.serializer.serialize(topic, envelope as unknown as Record<string, unknown>);
    await this.producer.send({
      topic,
      messages: [
        {
          key,
          value: Buffer.from(value),
          headers: { traceparent: trace.currentTraceparent() },
        },
      ],
    });
  }
}
