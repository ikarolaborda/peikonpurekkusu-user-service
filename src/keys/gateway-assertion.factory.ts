import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { KeysService } from './keys.service.js';

/**
 * Audience of the internal gateway assertion. Deliberately distinct from the
 * access token's JWT_AUDIENCE so the two ES256 tokens minted by this service
 * can never be confused: a leaked access token cannot be replayed as a gateway
 * assertion, and vice versa, because every downstream verifier pins this value.
 */
export const GATEWAY_ASSERTION_AUDIENCE = 'peikon-internal';

export interface GatewayAssertionClaims {
  sub: string;
  roles: string[];
  sid: string;
  amr: string[];
  auth_time: number;
}

/**
 * Mints the short-lived assertion that proves an inbound request genuinely
 * passed ForwardAuth at user-service, rather than being a peer on the internal
 * network forging X-User-Id. It carries the same identity ForwardAuth already
 * hands downstream (id, roles, session, auth strength), but signed — so a
 * consumer trusts the *claims*, not the raw headers. Signed with the B6 ES256
 * key ring; consumers verify through the published JWKS. TTL is short because
 * the only defence against replay on the internal net is the expiry window.
 */
@Injectable()
export class GatewayAssertionFactory {
  private readonly ttlSeconds: number;
  private readonly issuer: string;

  constructor(
    private readonly keys: KeysService,
    config: ConfigService,
  ) {
    this.ttlSeconds = Number(config.getOrThrow('GATEWAY_ASSERTION_TTL'));
    this.issuer = config.getOrThrow('JWT_ISSUER');
  }

  async issue(claims: GatewayAssertionClaims): Promise<string> {
    return new jose.SignJWT({
      roles: claims.roles,
      sid: claims.sid,
      amr: claims.amr,
      auth_time: claims.auth_time,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: this.keys.kid })
      .setSubject(claims.sub)
      .setIssuer(this.issuer)
      .setAudience(GATEWAY_ASSERTION_AUDIENCE)
      .setIssuedAt()
      .setNotBefore('0s')
      .setExpirationTime(`${this.ttlSeconds}s`)
      .sign(this.keys.signingKey());
  }
}
