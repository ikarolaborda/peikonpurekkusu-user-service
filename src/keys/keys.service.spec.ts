import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeysService } from './keys.service.js';
import { TokenFactory } from './token.factory.js';

interface TestKey {
  privatePem: string;
  publicPem: string;
  kid: string;
}

function newKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    kid,
  };
}

describe('KeysService key ring', () => {
  let dir: string;

  const configFor = (current: TestKey, retiredDir?: string): ConfigService => {
    writeFileSync(join(dir, 'current.pem'), current.privatePem);
    writeFileSync(join(dir, 'current.kid'), current.kid);
    const values: Record<string, string> = {
      JWT_PRIVATE_KEY_PATH: join(dir, 'current.pem'),
      JWT_KID_PATH: join(dir, 'current.kid'),
      ACCESS_TOKEN_TTL: '600',
      JWT_ISSUER: 'test-issuer',
      JWT_AUDIENCE: 'test-audience',
    };
    if (retiredDir) values.JWT_RETIRED_KEYS_DIR = retiredDir;
    return {
      get: (k: string) => values[k],
      getOrThrow: (k: string) => {
        if (!(k in values)) throw new Error(`missing config ${k}`);
        return values[k];
      },
    } as unknown as ConfigService;
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'b6-keys-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('serves a ring of one when no retired directory is configured', async () => {
    const svc = new KeysService(configFor(newKey('aaaaaaaabbbbbbbb')));
    await svc.onModuleInit();
    expect(svc.jwks().keys.map((k) => k.kid)).toEqual(['aaaaaaaabbbbbbbb']);
  });

  it('keeps a pre-rotation token valid when the old key is retired', async () => {
    const oldKey = newKey('aaaaaaaa11111111');
    const preRotation = new TokenFactory(
      await initialized(new KeysService(configFor(oldKey))),
      configFor(oldKey),
    );
    const { token } = await preRotation.issueAccessToken({
      sub: 'u1', sid: 's1', roles: [], amr: ['pwd'], auth_time: Math.floor(Date.now() / 1000),
    });

    const retired = join(dir, 'retired');
    mkdirSync(retired);
    writeFileSync(join(retired, `${oldKey.kid}.pem`), oldKey.publicPem);
    const newCurrent = newKey('bbbbbbbb22222222');
    const postRotation = new TokenFactory(
      await initialized(new KeysService(configFor(newCurrent, retired))),
      configFor(newCurrent, retired),
    );

    const payload = await postRotation.verifyAccessToken(token);
    expect(payload.sub).toBe('u1');
  });

  it('rejects the old token once its retired key is removed', async () => {
    const oldKey = newKey('aaaaaaaa11111111');
    const preRotation = new TokenFactory(
      await initialized(new KeysService(configFor(oldKey))),
      configFor(oldKey),
    );
    const { token } = await preRotation.issueAccessToken({
      sub: 'u1', sid: 's1', roles: [], amr: ['pwd'], auth_time: Math.floor(Date.now() / 1000),
    });

    const newCurrent = newKey('bbbbbbbb22222222');
    const postRemoval = new TokenFactory(
      await initialized(new KeysService(configFor(newCurrent))),
      configFor(newCurrent),
    );

    await expect(postRemoval.verifyAccessToken(token)).rejects.toThrow();
  });

  it('refuses to boot on a retired kid colliding with the current kid', async () => {
    const key = newKey('aaaaaaaa11111111');
    const retired = join(dir, 'retired');
    mkdirSync(retired);
    writeFileSync(join(retired, `${key.kid}.pem`), key.publicPem);
    const svc = new KeysService(configFor(key, retired));
    await expect(svc.onModuleInit()).rejects.toThrow(/duplicate kid/);
  });

  it('refuses to boot on a retired file with an invalid kid stem', async () => {
    const key = newKey('aaaaaaaa11111111');
    const retired = join(dir, 'retired');
    mkdirSync(retired);
    writeFileSync(join(retired, 'NOT-A-KID.pem'), newKey('cccccccc33333333').publicPem);
    const svc = new KeysService(configFor(key, retired));
    await expect(svc.onModuleInit()).rejects.toThrow(/invalid kid stem/);
  });

  it('rejects a token signed with an unknown key even at the right alg', async () => {
    const trusted = newKey('aaaaaaaa11111111');
    const rogue = newKey('dddddddd44444444');
    const rogueFactory = new TokenFactory(
      await initialized(new KeysService(configFor(rogue))),
      configFor(rogue),
    );
    const { token } = await rogueFactory.issueAccessToken({
      sub: 'intruder', sid: 's1', roles: [], amr: ['pwd'], auth_time: Math.floor(Date.now() / 1000),
    });

    const verifier = new TokenFactory(
      await initialized(new KeysService(configFor(trusted))),
      configFor(trusted),
    );
    await expect(verifier.verifyAccessToken(token)).rejects.toThrow();
  });

  it('rejects a token signed without a kid header', async () => {
    const key = newKey('aaaaaaaa11111111');
    const svc = await initialized(new KeysService(configFor(key)));
    const factory = new TokenFactory(svc, configFor(key));
    const noKid = await new jose.SignJWT({ sid: 's1' })
      .setProtectedHeader({ alg: 'ES256' })
      .setSubject('u1')
      .setIssuer('test-issuer')
      .setAudience('test-audience')
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(svc.signingKey());
    await expect(factory.verifyAccessToken(noKid)).rejects.toThrow();
  });

  it('publishes only public JWK members in the JWKS', async () => {
    const svc = await initialized(new KeysService(configFor(newKey('aaaaaaaa11111111'))));
    for (const key of svc.jwks().keys) {
      expect(key).not.toHaveProperty('d');
      expect(key.kty).toBe('EC');
      expect(key.use).toBe('sig');
    }
  });

  async function initialized(svc: KeysService): Promise<KeysService> {
    await svc.onModuleInit();
    return svc;
  }
});
