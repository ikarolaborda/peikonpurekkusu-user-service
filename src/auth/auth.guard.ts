import {
  CanActivate,
  createParamDecorator,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { AuthService, VerifiedPrincipal } from './auth.service.js';

declare module 'express' {
  interface Request {
    principal?: VerifiedPrincipal;
  }
}

/**
 * Guards /auth-scoped endpoints that need an authenticated caller (logout,
 * sessions). Everything routed through Traefik's jwt-auth middleware is
 * verified at the edge instead; this guard exists because /auth/* is
 * deliberately outside that middleware. Chain-of-responsibility with
 * CsrfGuard: AuthGuard authenticates, CsrfGuard authorizes the mutation.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly accessCookie: string;

  constructor(
    private readonly auth: AuthService,
    config: ConfigService,
  ) {
    this.accessCookie = config.getOrThrow('COOKIE_ACCESS_NAME');
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const token =
      (req.cookies?.[this.accessCookie] as string | undefined) ??
      req.headers.authorization?.replace(/^Bearer /, '');
    if (!token) throw new UnauthorizedException('not authenticated');
    req.principal = await this.auth.verify(token);
    return true;
  }
}

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    if (!req.principal) throw new UnauthorizedException('not authenticated');
    this.auth.verifyCsrf(req.headers['x-csrf-token'] as string | undefined, req.principal.csrfSecret);
    return true;
  }
}

export const Principal = createParamDecorator((_data: unknown, ctx: ExecutionContext): VerifiedPrincipal => {
  const req = ctx.switchToHttp().getRequest<Request>();
  if (!req.principal) throw new UnauthorizedException('not authenticated');
  return req.principal;
});
