import { EntityManager } from '@mikro-orm/postgresql';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomInt, timingSafeEqual } from 'node:crypto';
import { User } from '../entities/user.entity.js';
import { SessionsService } from '../sessions/sessions.service.js';
import type { MfaChannelStrategy } from './mfa.strategy.js';

export const MFA_STRATEGIES = Symbol('MFA_STRATEGIES');
const CODE_TTL_SECONDS = 300;

/**
 * Issues and verifies step-up challenges, and drives self-service enrollment.
 * A successful login-time verification elevates the session (fresh auth_time +
 * amr += mfa) — high-risk operations demand a recent auth_time, so an
 * old-but-valid stolen token cannot move money. Enrollment deliberately does
 * NOT elevate: proving deliverability to turn the feature on is not a step-up
 * event, and must not satisfy a payment freshness check.
 */
@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);

  constructor(
    private readonly sessions: SessionsService,
    private readonly em: EntityManager,
    @Inject(MFA_STRATEGIES) private readonly strategies: MfaChannelStrategy[],
  ) {}

  async challenge(sessionId: string, channel = 'email'): Promise<void> {
    const strategy = this.strategies.find((s) => s.name === channel) ?? this.strategies[0];
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    await this.sessions.setEphemeral(`mfa:${sessionId}`, code, CODE_TTL_SECONDS);
    await strategy.deliver(sessionId, code);
  }

  async verify(sessionId: string, code: string): Promise<boolean> {
    if (!(await this.checkCode(sessionId, code))) {
      return false;
    }
    await this.sessions.elevate(sessionId, ['pwd', 'mfa']);
    return true;
  }

  async isEnrolled(userId: string): Promise<boolean> {
    const user = await this.em.fork().findOne(User, { id: userId });
    return user?.mfaEnrolled ?? false;
  }

  /**
   * Confirms enrollment: the user must prove they can receive a code BEFORE the
   * flag flips, otherwise a broken channel would lock them out of their next
   * login. Unlike verify(), this does not elevate the session — enrollment is a
   * setup action, not a step-up.
   */
  async confirmEnrollment(sessionId: string, userId: string, code: string): Promise<boolean> {
    if (!(await this.checkCode(sessionId, code))) {
      return false;
    }
    const em = this.em.fork();
    const user = await em.findOne(User, { id: userId });
    if (!user) {
      return false;
    }
    user.mfaEnrolled = true;
    await em.flush();
    this.logger.log(`MFA enrolled for user ${userId}`);
    return true;
  }

  async disable(userId: string): Promise<void> {
    const em = this.em.fork();
    const user = await em.findOne(User, { id: userId });
    if (!user || !user.mfaEnrolled) {
      return;
    }
    user.mfaEnrolled = false;
    await em.flush();
    this.logger.log(`MFA disabled for user ${userId}`);
  }

  /** Timing-safe compare that consumes the code on success, so it cannot be replayed. */
  private async checkCode(sessionId: string, code: string): Promise<boolean> {
    const key = `mfa:${sessionId}`;
    const expected = await this.sessions.getEphemeral(key);
    if (!expected || expected.length !== code.length) {
      return false;
    }
    if (!timingSafeEqual(Buffer.from(expected), Buffer.from(code))) {
      return false;
    }
    await this.sessions.delEphemeral(key);
    return true;
  }
}
