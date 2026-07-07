import { MikroORM } from '@mikro-orm/postgresql';
import { Controller, Get } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckResult,
  HealthCheckService,
  HealthIndicatorService,
} from '@nestjs/terminus';
import { KafkaProducerService } from '../messaging/kafka-producer.service.js';
import { SessionsService } from '../sessions/sessions.service.js';

@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly indicator: HealthIndicatorService,
    private readonly orm: MikroORM,
    private readonly sessions: SessionsService,
    private readonly kafka: KafkaProducerService,
  ) {}

  /** Liveness: process only — dependency blips must not restart the container. */
  @Get('live')
  live(): { status: string } {
    return { status: 'ok' };
  }

  @Get('ready')
  @HealthCheck()
  ready(): Promise<HealthCheckResult> {
    return this.health.check([
      async () => {
        const ind = this.indicator.check('postgres');
        const ok = await this.orm.isConnected();
        return ok ? ind.up() : ind.down();
      },
      async () => {
        const ind = this.indicator.check('redis-session');
        try {
          await this.sessions.ping();
          return ind.up();
        } catch {
          return ind.down();
        }
      },
      async () => {
        const ind = this.indicator.check('kafka');
        return this.kafka.isConnected() ? ind.up() : ind.down();
      },
    ]);
  }
}
