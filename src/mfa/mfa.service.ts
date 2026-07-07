import { Inject, Injectable } from '@nestjs/common';
import { randomInt, timingSafeEqual } from 'node:crypto';
import { SessionsService } from '../sessions/sessions.service.js';
import type { MfaChannelStrategy } from './mfa.strategy.js';

export const MFA_STRATEGIES = Symbol('MFA_STRATEGIES');
const CODE_TTL_SECONDS = 300;

/**
 * Issues and verifies step-up challenges. Successful verification elevates
 * the session (fresh auth_time + amr += mfa) — high-risk operations demand a
 * recent auth_time, so an old-but-valid stolen token cannot move money.
 */
@Injectable()
export class MfaService {
  constructor(
    private readonly sessions: SessionsService,
    @Inject(MFA_STRATEGIES) private readonly strategies: MfaChannelStrategy[],
  ) {}

  async challenge(sessionId: string, channel = 'email'): Promise<void> {
    const strategy = this.strategies.find((s) => s.name === channel) ?? this.strategies[0];
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    await this.sessions.setEphemeral(`mfa:${sessionId}`, code, CODE_TTL_SECONDS);
    await strategy.deliver(sessionId, code);
  }

  async verify(sessionId: string, code: string): Promise<boolean> {
    const key = `mfa:${sessionId}`;
    const expected = await this.sessions.getEphemeral(key);
    if (!expected || expected.length !== code.length) return false;
    if (!timingSafeEqual(Buffer.from(expected), Buffer.from(code))) return false;
    await this.sessions.delEphemeral(key);
    await this.sessions.elevate(sessionId, ['pwd', 'mfa']);
    return true;
  }
}
