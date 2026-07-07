import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { randomUUID } from 'node:crypto';
import { KeysService } from './keys.service.js';

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  roles: string[];
  amr: string[];
  auth_time: number;
}

export interface IssuedAccessToken {
  token: string;
  jti: string;
  expiresAt: Date;
}

/**
 * Factory for access tokens. Short TTL (default 10 min) is the first theft
 * mitigation; `jti` enables the Redis denylist; `sid` ties the token to a
 * revocable server-side session.
 */
@Injectable()
export class TokenFactory {
  private readonly ttlSeconds: number;
  private readonly issuer: string;
  private readonly audience: string;

  constructor(
    private readonly keys: KeysService,
    config: ConfigService,
  ) {
    this.ttlSeconds = Number(config.getOrThrow('ACCESS_TOKEN_TTL'));
    this.issuer = config.getOrThrow('JWT_ISSUER');
    this.audience = config.getOrThrow('JWT_AUDIENCE');
  }

  async issueAccessToken(claims: AccessTokenClaims): Promise<IssuedAccessToken> {
    const jti = randomUUID();
    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1000);
    const token = await new jose.SignJWT({
      roles: claims.roles,
      sid: claims.sid,
      amr: claims.amr,
      auth_time: claims.auth_time,
    })
      .setProtectedHeader({ alg: 'ES256', kid: this.keys.kid })
      .setSubject(claims.sub)
      .setJti(jti)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt()
      .setNotBefore('0s')
      .setExpirationTime(`${this.ttlSeconds}s`)
      .sign(this.keys.signingKey());
    return { token, jti, expiresAt };
  }

  /**
   * Verifies one of our own tokens. Algorithm allow-list is pinned — header
   * key sources (jku/jwk/x5u) are never honored by jose's key-object path.
   */
  async verifyAccessToken(token: string): Promise<jose.JWTPayload> {
    const { payload } = await jose.jwtVerify(token, await this.keys.verificationKey(), {
      algorithms: ['ES256'],
      issuer: this.issuer,
      audience: this.audience,
      clockTolerance: '5s',
    });
    return payload;
  }
}
