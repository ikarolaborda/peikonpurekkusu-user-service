import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'node:crypto';
import { createClient, type RedisClientType } from 'redis';

export interface SessionRecord {
  userId: string;
  createdAt: number;
  authTime: number;
  amr: string[];
  fingerprintHash: string;
  ip: string;
  csrfSecret: string;
}

/**
 * Server-side session state in redis-session (noeviction + AOF — this data
 * must never be silently evicted). Also owns the jti/sid denylists that make
 * "revoke now" real despite stateless JWTs.
 *
 * FAIL CLOSED: any Redis error on a check path surfaces as 503 — a revoked
 * (possibly stolen) token must never be accepted because the denylist was
 * unreachable.
 */
@Injectable()
export class SessionsService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SessionsService.name);
  private client: RedisClientType;
  private readonly refreshTtlSeconds: number;

  constructor(config: ConfigService) {
    this.refreshTtlSeconds = Number(config.getOrThrow('REFRESH_TOKEN_TTL'));
    this.client = createClient({
      socket: {
        host: config.getOrThrow('REDIS_SESSION_HOST'),
        port: Number(config.getOrThrow('REDIS_SESSION_PORT')),
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
      },
      password: config.getOrThrow('REDIS_SESSION_PASSWORD'),
    });
    this.client.on('error', (err) => this.logger.error(`redis-session: ${err.message}`));
  }

  async onModuleInit(): Promise<void> {
    await this.client.connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.destroy();
  }

  async ping(): Promise<void> {
    await this.client.ping();
  }

  async create(record: Omit<SessionRecord, 'csrfSecret'>): Promise<{ sessionId: string; csrfSecret: string }> {
    const sessionId = randomBytes(24).toString('base64url');
    const csrfSecret = randomBytes(24).toString('base64url');
    const key = `session:${sessionId}`;
    await this.client
      .multi()
      .hSet(key, {
        userId: record.userId,
        createdAt: String(record.createdAt),
        authTime: String(record.authTime),
        amr: record.amr.join(','),
        fingerprintHash: record.fingerprintHash,
        ip: record.ip,
        csrfSecret,
      })
      .expire(key, this.refreshTtlSeconds)
      .sAdd(`user:${record.userId}:sessions`, sessionId)
      .exec();
    return { sessionId, csrfSecret };
  }

  async get(sessionId: string): Promise<SessionRecord | null> {
    const raw = await this.client.hGetAll(`session:${sessionId}`);
    if (!raw || !raw.userId) return null;
    return {
      userId: raw.userId,
      createdAt: Number(raw.createdAt),
      authTime: Number(raw.authTime),
      amr: raw.amr ? raw.amr.split(',') : [],
      fingerprintHash: raw.fingerprintHash ?? '',
      ip: raw.ip ?? '',
      csrfSecret: raw.csrfSecret ?? '',
    };
  }

  /** Sliding expiration on authenticated activity. */
  async touch(sessionId: string): Promise<void> {
    await this.client.expire(`session:${sessionId}`, this.refreshTtlSeconds);
  }

  async elevate(sessionId: string, amr: string[]): Promise<void> {
    await this.client.hSet(`session:${sessionId}`, {
      authTime: String(Math.floor(Date.now() / 1000)),
      amr: amr.join(','),
    });
  }

  async destroy(sessionId: string, userId: string): Promise<void> {
    await this.client
      .multi()
      .del(`session:${sessionId}`)
      .sRem(`user:${userId}:sessions`, sessionId)
      .exec();
  }

  async listSessionIds(userId: string): Promise<string[]> {
    return this.client.sMembers(`user:${userId}:sessions`);
  }

  /** Short-lived auxiliary values (MFA codes, one-time state) — same durability class as sessions. */
  async setEphemeral(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.client.set(key, value, { expiration: { type: 'EX', value: ttlSeconds } });
  }

  async getEphemeral(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async delEphemeral(key: string): Promise<void> {
    await this.client.del(key);
  }

  /** Denylist an access token until it would have expired anyway. */
  async denylistJti(jti: string, expiresAt: Date): Promise<void> {
    const ttl = Math.max(1, Math.ceil((expiresAt.getTime() - Date.now()) / 1000));
    await this.client.set(`revoked:jti:${jti}`, '1', { expiration: { type: 'EX', value: ttl } });
  }

  /** Session-wide kill switch — catches every access token bound to the sid. */
  async denylistSession(sessionId: string, ttlSeconds: number): Promise<void> {
    await this.client.set(`revoked:sid:${sessionId}`, '1', {
      expiration: { type: 'EX', value: Math.max(1, ttlSeconds) },
    });
  }

  /**
   * The verify hot path. Throws 503 when Redis is down — fail closed.
   */
  async isRevoked(jti: string, sessionId: string): Promise<boolean> {
    try {
      const [byJti, bySid] = await Promise.all([
        this.client.exists(`revoked:jti:${jti}`),
        this.client.exists(`revoked:sid:${sessionId}`),
      ]);
      return byJti === 1 || bySid === 1;
    } catch (err) {
      this.logger.error(`denylist check failed — failing closed: ${(err as Error).message}`);
      throw new ServiceUnavailableException('authorization backend unavailable');
    }
  }
}
