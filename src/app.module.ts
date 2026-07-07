import { MikroOrmModule } from '@mikro-orm/nestjs';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TerminusModule } from '@nestjs/terminus';
import type { NextFunction, Request, Response } from 'express';
import mikroOrmConfig from '../mikro-orm.config.js';
import { AuthController } from './auth/auth.controller.js';
import { AuthGuard, CsrfGuard } from './auth/auth.guard.js';
import { AuthService } from './auth/auth.service.js';
import { validateEnv } from './config/env.validation.js';
import { OutboxEvent } from './entities/outbox-event.entity.js';
import { RefreshToken } from './entities/refresh-token.entity.js';
import { User } from './entities/user.entity.js';
import { HealthController } from './health/health.controller.js';
import { JwksController } from './keys/jwks.controller.js';
import { KeysService } from './keys/keys.service.js';
import { TokenFactory } from './keys/token.factory.js';
import { EventEnvelopeFactory } from './messaging/event-envelope.factory.js';
import { KafkaProducerService } from './messaging/kafka-producer.service.js';
import { OutboxRelayService } from './messaging/outbox-relay.service.js';
import { trace } from './messaging/trace-context.js';
import { MfaService, MFA_STRATEGIES } from './mfa/mfa.service.js';
import { EmailMockStrategy, TotpMockStrategy } from './mfa/mfa.strategy.js';
import { SessionsService } from './sessions/sessions.service.js';
import { UsersController } from './users/users.controller.js';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, cache: true, validate: validateEnv }),
    MikroOrmModule.forRoot(mikroOrmConfig),
    MikroOrmModule.forFeature([User, RefreshToken, OutboxEvent]),
    TerminusModule,
  ],
  controllers: [AuthController, UsersController, JwksController, HealthController],
  providers: [
    KeysService,
    TokenFactory,
    SessionsService,
    AuthService,
    AuthGuard,
    CsrfGuard,
    MfaService,
    { provide: MFA_STRATEGIES, useValue: [new EmailMockStrategy(), new TotpMockStrategy()] },
    EventEnvelopeFactory,
    KafkaProducerService,
    OutboxRelayService,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Seed the per-request trace context from the inbound W3C traceparent.
    consumer
      .apply((req: Request, _res: Response, next: NextFunction) =>
        trace.run(req.headers.traceparent as string | undefined, next),
      )
      .forRoutes('*');
  }
}
