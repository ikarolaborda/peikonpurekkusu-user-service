import { EntityManager } from '@mikro-orm/postgresql';
import {
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { OutboxEvent } from '../entities/outbox-event.entity.js';
import { RefreshToken, type RefreshTokenEntity } from '../entities/refresh-token.entity.js';
import { User, UserStatus, type UserEntity } from '../entities/user.entity.js';
import { TokenFactory } from '../keys/token.factory.js';
import { SessionsService } from '../sessions/sessions.service.js';

export interface CookiePair {
  accessToken: string;
  accessExpiresAt: Date;
  refreshToken: string;
  refreshExpiresAt: Date;
}

export interface LoginResult extends CookiePair {
  csrfToken: string;
  mfaRequired: boolean;
  sessionId: string;
}

export interface VerifiedPrincipal {
  userId: string;
  sessionId: string;
  roles: string[];
  jti: string;
  csrfSecret: string;
  expiresAt: Date;
}

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

/**
 * AuthFacade — single entry point over credentials, sessions, token issuance,
 * rotation and revocation (Facade pattern). Controllers never touch the
 * subsystems directly.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly refreshTtlMs: number;
  private readonly reuseGraceMs: number;

  constructor(
    private readonly em: EntityManager,
    private readonly tokens: TokenFactory,
    private readonly sessions: SessionsService,
    config: ConfigService,
  ) {
    this.refreshTtlMs = Number(config.getOrThrow('REFRESH_TOKEN_TTL')) * 1000;
    this.reuseGraceMs = Number(config.getOrThrow('REFRESH_REUSE_GRACE_MS'));
  }

  async register(input: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  }): Promise<{ userId: string }> {
    const em = this.em.fork();
    const user = em.create(User, {
      email: input.email.toLowerCase(),
      passwordHash: await argon2.hash(input.password),
      firstName: input.firstName,
      lastName: input.lastName,
    });
    em.persist(user);
    em.persist(
      em.create(OutboxEvent, {
        aggregatetype: 'user',
        aggregateid: user.id,
        type: 'identity.user.registered.v1',
        payload: {
          user_id: user.id,
          kyc_status: user.kycStatus,
          registered_at: user.createdAt.toISOString(),
        },
      }),
    );
    await em.flush(); // user + outbox in one transaction (UoW)
    return { userId: user.id };
  }

  async login(input: {
    email: string;
    password: string;
    fingerprint: string;
    ip: string;
  }): Promise<LoginResult> {
    const em = this.em.fork();
    const user = await em.findOne(User, { email: input.email.toLowerCase() });
    // Verify against a constant dummy hash when the user is unknown so the
    // response time does not reveal account existence.
    const hash =
      user?.passwordHash ??
      '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$SbUZbdrbYDBhq3HRs2GNjkGjkS+wZ5PZuJJZ0M1P8Fk';
    const valid = await argon2.verify(hash, input.password).catch(() => false);
    if (!user || !valid) throw new UnauthorizedException('invalid credentials');
    if (user.status === UserStatus.FROZEN) throw new ForbiddenException('account frozen');

    if (argon2.needsRehash(user.passwordHash)) {
      user.passwordHash = await argon2.hash(input.password);
      await em.flush();
    }

    const now = Math.floor(Date.now() / 1000);
    const { sessionId, csrfSecret } = await this.sessions.create({
      userId: user.id,
      createdAt: now,
      authTime: now,
      amr: ['pwd'],
      fingerprintHash: sha256(input.fingerprint || 'unknown'),
      ip: input.ip,
    });

    const pair = await this.issuePair(em, user, sessionId, randomUUID(), 0, input.fingerprint);
    await em.flush();
    return {
      ...pair,
      csrfToken: csrfSecret,
      mfaRequired: user.mfaEnrolled,
      sessionId,
    };
  }

  /**
   * RFC 9700 rotation: the presented refresh token is consumed atomically;
   * reuse of an already-consumed token outside the grace window is treated as
   * theft — the entire family and its session die, and a security event is
   * emitted through the outbox.
   */
  async refresh(rawRefreshToken: string, fingerprint: string): Promise<CookiePair & { csrfToken: string }> {
    const em = this.em.fork();
    const tokenHash = sha256(rawRefreshToken);
    const existing = await em.findOne(RefreshToken, { tokenHash });
    if (!existing) throw new UnauthorizedException('unknown refresh token');
    if (existing.revokedAt) throw new UnauthorizedException('refresh token revoked');
    if (existing.expiresAt.getTime() < Date.now()) throw new UnauthorizedException('refresh token expired');

    if (existing.consumedAt) {
      const sinceConsume = Date.now() - existing.consumedAt.getTime();
      if (sinceConsume > this.reuseGraceMs) {
        await this.revokeFamily(em, existing, 'refresh_reuse_detected');
        await em.flush();
        this.logger.warn(`refresh reuse detected — family ${existing.familyId} revoked`);
      }
      // Inside the grace window this is a parallel-tab race, not necessarily
      // theft: reject without collateral damage; the SPA serializes retries.
      throw new UnauthorizedException('refresh token already used');
    }

    // Atomic consume — only one concurrent request wins this UPDATE.
    const consumed = await em
      .getConnection()
      .execute(
        `update refresh_tokens set consumed_at = now() where id = ? and consumed_at is null`,
        [existing.id],
      );
    if ((consumed as { affectedRows?: number }).affectedRows === 0) {
      throw new UnauthorizedException('refresh token already used');
    }

    const session = await this.sessions.get(existing.sessionId);
    if (!session) throw new UnauthorizedException('session expired');
    if (session.fingerprintHash !== sha256(fingerprint || 'unknown')) {
      await this.revokeFamily(em, existing, 'refresh_reuse_detected');
      await em.flush();
      throw new UnauthorizedException('session context changed — reauthenticate');
    }

    const user = await em.findOne(User, { id: existing.userId });
    if (!user || user.status === UserStatus.FROZEN) {
      throw new UnauthorizedException('account unavailable');
    }

    const pair = await this.issuePair(
      em,
      user,
      existing.sessionId,
      existing.familyId,
      existing.generation + 1,
      fingerprint,
    );
    await em.flush();
    await this.sessions.touch(existing.sessionId);
    return { ...pair, csrfToken: session.csrfSecret };
  }

  async logout(principal: { userId: string; sessionId: string; jti: string; expiresAt: Date }): Promise<void> {
    const em = this.em.fork();
    await this.sessions.denylistJti(principal.jti, principal.expiresAt);
    await this.sessions.denylistSession(principal.sessionId, Math.ceil(this.refreshTtlMs / 1000));
    await this.sessions.destroy(principal.sessionId, principal.userId);
    const anyToken = await em.findOne(RefreshToken, {
      sessionId: principal.sessionId,
      revokedAt: null,
    });
    if (anyToken) {
      await this.revokeFamily(em, anyToken, 'logout');
      await em.flush();
    }
  }

  async revokeOtherSessions(principal: { userId: string; sessionId: string }): Promise<number> {
    const em = this.em.fork();
    const ids = await this.sessions.listSessionIds(principal.userId);
    let revoked = 0;
    for (const sid of ids.filter((s) => s !== principal.sessionId)) {
      await this.sessions.denylistSession(sid, Math.ceil(this.refreshTtlMs / 1000));
      await this.sessions.destroy(sid, principal.userId);
      const token = await em.findOne(RefreshToken, { sessionId: sid, revokedAt: null });
      if (token) await this.revokeFamily(em, token, 'admin_revoke');
      revoked += 1;
    }
    await em.flush();
    return revoked;
  }

  /**
   * ForwardAuth hot path: signature + claims + denylist + session binding.
   * Redis failures inside isRevoked() bubble as 503 (fail closed).
   */
  async verify(accessToken: string): Promise<VerifiedPrincipal> {
    let payload;
    try {
      payload = await this.tokens.verifyAccessToken(accessToken);
    } catch {
      throw new UnauthorizedException('invalid token');
    }
    const jti = payload.jti as string;
    const sessionId = payload.sid as string;
    if (!jti || !sessionId) throw new UnauthorizedException('malformed token');

    if (await this.sessions.isRevoked(jti, sessionId)) {
      throw new UnauthorizedException('token revoked');
    }
    const session = await this.sessions.get(sessionId);
    if (!session) throw new UnauthorizedException('session expired');

    return {
      userId: payload.sub as string,
      sessionId,
      roles: (payload.roles as string[]) ?? [],
      jti,
      csrfSecret: session.csrfSecret,
      expiresAt: new Date((payload.exp as number) * 1000),
    };
  }

  verifyCsrf(headerToken: string | undefined, csrfSecret: string): void {
    if (!headerToken || headerToken.length !== csrfSecret.length) {
      throw new ForbiddenException('missing or invalid CSRF token');
    }
    if (!timingSafeEqual(Buffer.from(headerToken), Buffer.from(csrfSecret))) {
      throw new ForbiddenException('missing or invalid CSRF token');
    }
  }

  private async issuePair(
    em: EntityManager,
    user: UserEntity,
    sessionId: string,
    familyId: string,
    generation: number,
    fingerprint: string,
  ): Promise<CookiePair> {
    const session = await this.sessions.get(sessionId);
    const access = await this.tokens.issueAccessToken({
      sub: user.id,
      sid: sessionId,
      roles: user.roles,
      amr: session?.amr ?? ['pwd'],
      auth_time: session?.authTime ?? Math.floor(Date.now() / 1000),
    });

    const rawRefresh = randomBytes(32).toString('base64url');
    const refreshExpiresAt = new Date(Date.now() + this.refreshTtlMs);
    em.persist(
      em.create(RefreshToken, {
        userId: user.id,
        familyId,
        generation,
        tokenHash: sha256(rawRefresh),
        sessionId,
        deviceFingerprintHash: sha256(fingerprint || 'unknown'),
        expiresAt: refreshExpiresAt,
      }),
    );

    return {
      accessToken: access.token,
      accessExpiresAt: access.expiresAt,
      refreshToken: rawRefresh,
      refreshExpiresAt,
    };
  }

  private async revokeFamily(em: EntityManager, member: RefreshTokenEntity, reason: string): Promise<void> {
    await em
      .getConnection()
      .execute(`update refresh_tokens set revoked_at = now() where family_id = ? and revoked_at is null`, [
        member.familyId,
      ]);
    await this.sessions.denylistSession(member.sessionId, Math.ceil(this.refreshTtlMs / 1000));
    await this.sessions.destroy(member.sessionId, member.userId);
    em.persist(
      em.create(OutboxEvent, {
        aggregatetype: 'user',
        aggregateid: member.userId,
        type: 'identity.user.session_revoked.v1',
        payload: {
          user_id: member.userId,
          session_id: member.sessionId,
          reason,
          family_wide: true,
        },
      }),
    );
  }
}
