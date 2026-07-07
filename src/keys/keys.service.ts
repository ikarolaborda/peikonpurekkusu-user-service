import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { readFileSync } from 'node:fs';

/**
 * Holds the ES256 signing material. This service is the ONLY holder of the
 * private key in the whole platform; every other party verifies through the
 * published JWKS. `kid` rotation: drop a new PEM+kid in /secrets and restart —
 * old public keys stay in the JWKS until their tokens expire.
 */
@Injectable()
export class KeysService implements OnModuleInit {
  private readonly logger = new Logger(KeysService.name);
  private privateKey: jose.CryptoKey;
  private publicJwk: jose.JWK;
  kid: string;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const rawPem = readFileSync(this.config.getOrThrow<string>('JWT_PRIVATE_KEY_PATH'), 'utf8');
    this.kid = readFileSync(this.config.getOrThrow<string>('JWT_KID_PATH'), 'utf8').trim();
    // Normalize SEC1/PKCS#1 PEMs to PKCS#8 — jose accepts only PKCS#8.
    const { createPrivateKey } = await import('node:crypto');
    const pem = createPrivateKey(rawPem).export({ type: 'pkcs8', format: 'pem' }) as string;
    this.privateKey = await jose.importPKCS8(pem, 'ES256');

    const publicKey = await jose.importSPKI(await this.derivePublicPem(rawPem), 'ES256');
    this.publicJwk = { ...(await jose.exportJWK(publicKey)), kid: this.kid, alg: 'ES256', use: 'sig' };
    this.logger.log(`ES256 signing key loaded (kid=${this.kid})`);
  }

  signingKey(): jose.CryptoKey {
    return this.privateKey;
  }

  /** Verification key for our own /verify hot path — no JWKS self-fetch. */
  async verificationKey(): Promise<jose.CryptoKey> {
    return (await jose.importJWK(this.publicJwk, 'ES256')) as jose.CryptoKey;
  }

  jwks(): { keys: jose.JWK[] } {
    return { keys: [this.publicJwk] };
  }

  private async derivePublicPem(privatePem: string): Promise<string> {
    const { createPrivateKey, createPublicKey } = await import('node:crypto');
    return createPublicKey(createPrivateKey(privatePem)).export({ type: 'spki', format: 'pem' }) as string;
  }
}
