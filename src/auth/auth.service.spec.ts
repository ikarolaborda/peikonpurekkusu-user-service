import { UnauthorizedException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { AuthService } from './auth.service';
import type { RefreshTokenEntity } from '../entities/refresh-token.entity';

const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

/** Minimal hand-rolled doubles — the invariants under test are pure control flow. */
function makeService(overrides: {
  existingToken?: Partial<RefreshTokenEntity>;
  user?: Record<string, unknown> | null;
  session?: Record<string, unknown> | null;
  graceMs?: number;
}) {
  const executed: Array<{ sql: string; params: unknown[] }> = [];
  const persisted: unknown[] = [];
  const connection = {
    execute: jest.fn(async (sql: string, params: unknown[]) => {
      executed.push({ sql, params });
      return { affectedRows: 1 };
    }),
  };
  const em = {
    fork: () => em,
    // First entity lookup in refresh() is the RefreshToken (by hash); the
    // second is the User (by id). Dispatch on the filter shape.
    findOne: jest.fn(async (_cls: unknown, where: Record<string, unknown>) => {
      if ('tokenHash' in where) return overrides.existingToken ?? null;
      if ('id' in where) {
        return overrides.user === null
          ? null
          : (overrides.user ?? { id: 'u1', roles: ['customer'], status: 'active' });
      }
      return null;
    }),
    getConnection: () => connection,
    persist: jest.fn((e: unknown) => persisted.push(e)),
    create: jest.fn((_cls: unknown, data: unknown) => data),
    flush: jest.fn(async () => undefined),
  };
  const sessions = {
    get: jest.fn(async () => overrides.session ?? null),
    touch: jest.fn(async () => undefined),
    create: jest.fn(async () => ({ sessionId: 's1', csrfSecret: 'c1' })),
    destroy: jest.fn(async () => undefined),
    denylistJti: jest.fn(async () => undefined),
    denylistSession: jest.fn(async () => undefined),
    listSessionIds: jest.fn(async () => []),
    isRevoked: jest.fn(async () => false),
  };
  const tokens = {
    issueAccessToken: jest.fn(async () => ({
      token: 'jwt',
      jti: randomUUID(),
      expiresAt: new Date(Date.now() + 600_000),
    })),
    verifyAccessToken: jest.fn(),
  };
  const config = {
    getOrThrow: (key: string) =>
      ({
        REFRESH_TOKEN_TTL: '1209600',
        REFRESH_REUSE_GRACE_MS: String(overrides.graceMs ?? 10_000),
      })[key],
  };
  const service = new AuthService(
    em as never,
    tokens as never,
    sessions as never,
    config as never,
  );
  return { service, em, sessions, executed, persisted };
}

const baseToken = (raw: string): Partial<RefreshTokenEntity> => ({
  id: randomUUID(),
  tokenHash: sha256(raw),
  familyId: randomUUID(),
  generation: 0,
  sessionId: 'sess-1',
  userId: 'u1',
  expiresAt: new Date(Date.now() + 86_400_000),
  consumedAt: undefined,
  revokedAt: undefined,
});

describe('AuthService refresh rotation (RFC 9700)', () => {
  const fp = 'device-1';
  const fpHash = sha256(fp);
  const liveSession = {
    userId: 'u1',
    createdAt: 0,
    authTime: 0,
    amr: ['pwd'],
    fingerprintHash: fpHash,
    ip: '',
    csrfSecret: 'csrf',
  };

  it('rotates an unconsumed token: consumes atomically and issues the next generation', async () => {
    const raw = 'refresh-raw';
    const { service, executed, persisted } = makeService({
      existingToken: baseToken(raw),
      session: liveSession,
    });
    const result = await service.refresh(raw, fp);
    expect(result.accessToken).toBe('jwt');
    expect(executed.some((e) => e.sql.includes('set consumed_at'))).toBe(true);
    const newToken = persisted.find(
      (p) => (p as RefreshTokenEntity).generation === 1,
    ) as RefreshTokenEntity;
    expect(newToken).toBeDefined();
    expect(newToken.tokenHash).not.toBe(sha256(raw));
  });

  it('reuse OUTSIDE the grace window revokes the family and emits session_revoked', async () => {
    const raw = 'stolen-refresh';
    const token = baseToken(raw);
    token.consumedAt = new Date(Date.now() - 60_000); // consumed a minute ago
    const { service, executed, persisted } = makeService({
      existingToken: token,
      session: liveSession,
      graceMs: 10_000,
    });
    await expect(service.refresh(raw, fp)).rejects.toThrow(UnauthorizedException);
    expect(executed.some((e) => e.sql.includes('set revoked_at') && e.sql.includes('family_id'))).toBe(true);
    const event = persisted.find(
      (p) => (p as { type?: string }).type === 'identity.user.session_revoked.v1',
    ) as { payload: { reason: string; family_wide: boolean } };
    expect(event).toBeDefined();
    expect(event.payload.reason).toBe('refresh_reuse_detected');
    expect(event.payload.family_wide).toBe(true);
  });

  it('reuse INSIDE the grace window rejects without family revocation (parallel-tab race)', async () => {
    const raw = 'racing-refresh';
    const token = baseToken(raw);
    token.consumedAt = new Date(Date.now() - 2_000); // 2s ago, grace is 10s
    const { service, executed } = makeService({ existingToken: token, session: liveSession });
    await expect(service.refresh(raw, fp)).rejects.toThrow('already used');
    expect(executed.some((e) => e.sql.includes('set revoked_at'))).toBe(false);
  });

  it('fingerprint mismatch on rotation revokes the family (session binding)', async () => {
    const raw = 'moved-refresh';
    const { service, executed } = makeService({
      existingToken: baseToken(raw),
      session: { ...liveSession, fingerprintHash: sha256('other-device') },
    });
    await expect(service.refresh(raw, fp)).rejects.toThrow('reauthenticate');
    expect(executed.some((e) => e.sql.includes('set revoked_at') && e.sql.includes('family_id'))).toBe(true);
  });

  it('rejects unknown, revoked and expired tokens outright', async () => {
    const { service } = makeService({ existingToken: undefined });
    await expect(service.refresh('nope', fp)).rejects.toThrow('unknown refresh token');

    const revoked = baseToken('revoked-raw');
    revoked.revokedAt = new Date();
    const { service: s2 } = makeService({ existingToken: revoked });
    await expect(s2.refresh('revoked-raw', fp)).rejects.toThrow('revoked');

    const expired = baseToken('expired-raw');
    expired.expiresAt = new Date(Date.now() - 1000);
    const { service: s3 } = makeService({ existingToken: expired });
    await expect(s3.refresh('expired-raw', fp)).rejects.toThrow('expired');
  });
});

describe('AuthService CSRF double-submit', () => {
  it('accepts only the exact session secret, in constant time', () => {
    const { service } = makeService({});
    expect(() => service.verifyCsrf('secret-1', 'secret-1')).not.toThrow();
    expect(() => service.verifyCsrf('secret-2', 'secret-1')).toThrow('CSRF');
    expect(() => service.verifyCsrf(undefined, 'secret-1')).toThrow('CSRF');
    expect(() => service.verifyCsrf('short', 'secret-1')).toThrow('CSRF');
  });
});
