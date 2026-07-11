import { MfaService } from './mfa.service';
import type { MfaChannelStrategy } from './mfa.strategy';

/** Minimal hand-rolled doubles — the invariants under test are pure control flow. */
function makeService(opts: { code?: string; user?: { mfaEnrolled: boolean } | null } = {}) {
  const store = new Map<string, string>();
  if (opts.code) {
    store.set('mfa:s1', opts.code);
  }
  const user = opts.user === undefined ? { mfaEnrolled: false } : opts.user;

  const elevate = jest.fn(async () => undefined);
  const sessions = {
    elevate,
    setEphemeral: jest.fn(async (k: string, v: string) => void store.set(k, v)),
    getEphemeral: jest.fn(async (k: string) => store.get(k) ?? null),
    delEphemeral: jest.fn(async (k: string) => void store.delete(k)),
  };

  const flush = jest.fn(async () => undefined);
  const em = {
    fork: () => em,
    findOne: jest.fn(async () => user),
    flush,
  };

  const strategies: MfaChannelStrategy[] = [{ name: 'email', deliver: jest.fn(async () => undefined) }];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const service = new MfaService(sessions as any, em as any, strategies);
  return { service, elevate, flush, user };
}

describe('MfaService enrollment', () => {
  it('enrolls a user only after a valid code', async () => {
    const { service, user } = makeService({ code: '123456', user: { mfaEnrolled: false } });
    expect(await service.confirmEnrollment('s1', 'u1', '123456')).toBe(true);
    expect(user!.mfaEnrolled).toBe(true);
  });

  it('rejects enrollment on a wrong code and leaves the flag off', async () => {
    const { service, user } = makeService({ code: '123456', user: { mfaEnrolled: false } });
    expect(await service.confirmEnrollment('s1', 'u1', '000000')).toBe(false);
    expect(user!.mfaEnrolled).toBe(false);
  });

  it('does not elevate the session on enrollment (setup is not a step-up)', async () => {
    const { service, elevate } = makeService({ code: '123456' });
    await service.confirmEnrollment('s1', 'u1', '123456');
    expect(elevate).not.toHaveBeenCalled();
  });

  it('consumes the code so it cannot be replayed', async () => {
    const { service, user } = makeService({ code: '123456', user: { mfaEnrolled: false } });
    expect(await service.confirmEnrollment('s1', 'u1', '123456')).toBe(true);
    user!.mfaEnrolled = false;
    expect(await service.confirmEnrollment('s1', 'u1', '123456')).toBe(false);
  });

  it('disables mfa for an enrolled user', async () => {
    const { service, user, flush } = makeService({ user: { mfaEnrolled: true } });
    await service.disable('u1');
    expect(user!.mfaEnrolled).toBe(false);
    expect(flush).toHaveBeenCalled();
  });
});
