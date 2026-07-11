import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

const KID_PATTERN = /^[a-f0-9]{8,64}$/;

/**
 * Key ring for the ES256 signing material. This service is the ONLY holder of
 * the private key in the whole platform; every other party verifies through
 * the published JWKS.
 *
 * Exactly one CURRENT signer (JWT_PRIVATE_KEY_PATH + JWT_KID_PATH) plus zero
 * or more RETIRED public keys (JWT_RETIRED_KEYS_DIR/<kid>.pem). Retired keys
 * keep pre-rotation access tokens verifiable for their remaining TTL; only
 * public halves are retained — a retired private key is a theft surface with
 * no remaining purpose. Rotation: move the current public pem into the retired
 * dir as <old-kid>.pem, install the new private pem + kid, restart; remove the
 * retired file once ACCESS_TOKEN_TTL plus clock tolerance has passed.
 */
@Injectable()
export class KeysService implements OnModuleInit {
  private readonly logger = new Logger(KeysService.name);
  private privateKey: jose.CryptoKey;
  private ring: jose.JWK[] = [];
  private verifier: ReturnType<typeof jose.createLocalJWKSet>;
  kid: string;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const rawPem = readFileSync(this.config.getOrThrow<string>('JWT_PRIVATE_KEY_PATH'), 'utf8');
    this.kid = readFileSync(this.config.getOrThrow<string>('JWT_KID_PATH'), 'utf8').trim();
    if (!KID_PATTERN.test(this.kid)) {
      throw new Error(`current kid '${this.kid}' does not match ${KID_PATTERN}`);
    }
    // Normalize SEC1/PKCS#1 PEMs to PKCS#8 — jose accepts only PKCS#8.
    const { createPrivateKey, createPublicKey } = await import('node:crypto');
    const pem = createPrivateKey(rawPem).export({ type: 'pkcs8', format: 'pem' }) as string;
    this.privateKey = await jose.importPKCS8(pem, 'ES256');

    const currentPublicPem = createPublicKey(createPrivateKey(rawPem))
      .export({ type: 'spki', format: 'pem' }) as string;
    this.ring = [await this.toJwk(currentPublicPem, this.kid)];

    for (const { kid, pem: retiredPem } of this.retiredPems()) {
      if (this.ring.some((k) => k.kid === kid)) {
        // A retired kid colliding with the current one would make acceptance
        // ambiguous during rotation — refuse to start rather than guess.
        throw new Error(`duplicate kid '${kid}' in key ring`);
      }
      this.ring.push(await this.toJwk(retiredPem, kid));
    }

    this.verifier = jose.createLocalJWKSet({ keys: this.ring });
    this.logger.log(
      `ES256 key ring loaded (signing kid=${this.kid}, ring=[${this.ring.map((k) => k.kid).join(', ')}])`,
    );
  }

  signingKey(): jose.CryptoKey {
    return this.privateKey;
  }

  /**
   * Ring verifier for our own /verify hot path — selects by the token's kid,
   * so tokens signed before a rotation stay valid while their key is retired
   * (not revoked). Unknown or missing kid fails verification.
   */
  verificationKeys(): ReturnType<typeof jose.createLocalJWKSet> {
    return this.verifier;
  }

  jwks(): { keys: jose.JWK[] } {
    return { keys: this.ring };
  }

  private retiredPems(): Array<{ kid: string; pem: string }> {
    const dir = this.config.get<string>('JWT_RETIRED_KEYS_DIR');
    if (!dir || !existsSync(dir)) {
      return [];
    }
    return readdirSync(dir)
      .filter((f) => f.endsWith('.pem'))
      .map((f) => {
        const kid = basename(f, '.pem');
        if (!KID_PATTERN.test(kid)) {
          throw new Error(`retired key file '${f}' has an invalid kid stem (want ${KID_PATTERN})`);
        }
        return { kid, pem: readFileSync(join(dir, f), 'utf8') };
      });
  }

  private async toJwk(publicPem: string, kid: string): Promise<jose.JWK> {
    const key = await jose.importSPKI(publicPem, 'ES256');
    const jwk = await jose.exportJWK(key);
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      throw new Error(`key '${kid}' is not an EC P-256 key (kty=${jwk.kty}, crv=${jwk.crv})`);
    }
    return { ...jwk, kid, alg: 'ES256', use: 'sig' };
  }
}
