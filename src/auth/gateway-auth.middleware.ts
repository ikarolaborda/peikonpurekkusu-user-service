import { Injectable, Logger, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import * as jose from 'jose';
import { GATEWAY_ASSERTION_AUDIENCE } from '../keys/gateway-assertion.factory.js';
import { KeysService } from '../keys/keys.service.js';

const IDENTITY_HEADERS = ['x-user-id', 'x-user-roles', 'x-session-id', 'x-auth-amr', 'x-auth-time'];

/**
 * Verifies the gateway assertion on user-service's own protected routes (e.g.
 * /users/me), so identity is trusted from a signed claim rather than a raw
 * x-user-id a peer on the internal network could forge. This service mints the
 * assertion, so it verifies against its own key ring locally — no self-HTTP.
 * Applied only to /users; /auth/* (the minter) and /.well-known bypass it.
 */
@Injectable()
export class GatewayAuthMiddleware implements NestMiddleware {
  private readonly logger = new Logger(GatewayAuthMiddleware.name);

  constructor(private readonly keys: KeysService) {}

  async use(req: Request, _res: Response, next: NextFunction): Promise<void> {
    const assertion = req.headers['x-gateway-assertion'];
    const token = Array.isArray(assertion) ? assertion[0] : assertion;
    if (!token) {
      throw new UnauthorizedException('missing gateway assertion');
    }

    let payload: jose.JWTPayload;
    try {
      ({ payload } = await jose.jwtVerify(token, this.keys.verificationKeys(), {
        algorithms: ['ES256'],
        audience: GATEWAY_ASSERTION_AUDIENCE,
        clockTolerance: '10s',
      }));
    } catch (err) {
      this.logger.warn(`gateway assertion rejected: ${(err as Error).message}`);
      throw new UnauthorizedException('invalid gateway assertion');
    }

    if (!payload.sub) {
      throw new UnauthorizedException('invalid gateway assertion');
    }

    for (const h of [...IDENTITY_HEADERS, 'x-gateway-assertion']) {
      delete req.headers[h];
    }
    req.headers['x-user-id'] = payload.sub;

    next();
  }
}
