import {
  Body,
  ConflictException,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Head,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { MfaService } from '../mfa/mfa.service.js';
import { SessionsService } from '../sessions/sessions.service.js';
import { AuthGuard, CsrfGuard, Principal } from './auth.guard.js';
import { AuthService, VerifiedPrincipal } from './auth.service.js';
import { clearAuthCookies, setAuthCookies } from './cookies.js';
import { LoginDto, MfaVerifyDto, RegisterDto } from './dto.js';
import { GatewayAssertionFactory } from '../keys/gateway-assertion.factory.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

@Controller('auth')
export class AuthController {
  private readonly cookiePolicy: { accessName: string; refreshName: string; secure: boolean };

  constructor(
    private readonly auth: AuthService,
    private readonly mfa: MfaService,
    private readonly sessions: SessionsService,
    private readonly gatewayAssertion: GatewayAssertionFactory,
    config: ConfigService,
  ) {
    this.cookiePolicy = {
      accessName: config.getOrThrow('COOKIE_ACCESS_NAME'),
      refreshName: config.getOrThrow('COOKIE_REFRESH_NAME'),
      secure: config.getOrThrow('COOKIE_SECURE') === 'true',
    };
  }

  @Post('register')
  @HttpCode(201)
  async register(@Body() dto: RegisterDto): Promise<{ user_id: string }> {
    const { userId } = await this.auth.register({
      email: dto.email,
      password: dto.password,
      firstName: dto.first_name,
      lastName: dto.last_name,
    });
    return { user_id: userId };
  }

  @Post('login')
  @HttpCode(200)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ csrf_token: string; mfa_required: boolean }> {
    const result = await this.auth.login({
      email: dto.email,
      password: dto.password,
      fingerprint: dto.device_fingerprint ?? '',
      ip: req.ip ?? '',
    });
    setAuthCookies(res, this.cookiePolicy, result);
    if (result.mfaRequired) await this.mfa.challenge(result.sessionId);
    return { csrf_token: result.csrfToken, mfa_required: result.mfaRequired };
  }

  @Post('mfa/verify')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(200)
  async mfaVerify(
    @Body() dto: MfaVerifyDto,
    @Principal() principal: VerifiedPrincipal,
  ): Promise<{ elevated: boolean }> {
    const ok = await this.mfa.verify(principal.sessionId, dto.code);
    if (!ok) throw new UnauthorizedException('invalid code');
    return { elevated: true };
  }

  // Self-service enrollment. Two steps so the flag flips only after the user
  // proves they can receive a code — enabling MFA against a channel that cannot
  // deliver would lock them out of their next login.
  @Post('mfa/enroll/start')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(202)
  async mfaEnrollStart(@Principal() principal: VerifiedPrincipal): Promise<void> {
    if (await this.mfa.isEnrolled(principal.userId)) {
      throw new ConflictException('already enrolled');
    }
    await this.mfa.challenge(principal.sessionId);
  }

  @Post('mfa/enroll/confirm')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(200)
  async mfaEnrollConfirm(
    @Body() dto: MfaVerifyDto,
    @Principal() principal: VerifiedPrincipal,
  ): Promise<{ mfa_enrolled: boolean }> {
    if (await this.mfa.isEnrolled(principal.userId)) {
      throw new ConflictException('already enrolled');
    }
    const ok = await this.mfa.confirmEnrollment(principal.sessionId, principal.userId, dto.code);
    if (!ok) {
      throw new UnauthorizedException('invalid code');
    }
    return { mfa_enrolled: true };
  }

  // Turning MFA off is a security downgrade, so it demands a session that has
  // actually completed MFA (amr includes 'mfa'), not merely a password-only one
  // — which AuthGuard still lets reach here so mfa-verify and logout keep working.
  @Post('mfa/disable')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(200)
  async mfaDisable(@Principal() principal: VerifiedPrincipal): Promise<{ mfa_enrolled: boolean }> {
    if (!principal.amr.includes('mfa')) {
      throw new ForbiddenException('recent MFA required to disable');
    }
    await this.mfa.disable(principal.userId);
    return { mfa_enrolled: false };
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ csrf_token: string }> {
    const raw = req.cookies?.[this.cookiePolicy.refreshName] as string | undefined;
    if (!raw) throw new UnauthorizedException('no refresh token');
    const fingerprint = (req.headers['x-device-fingerprint'] as string | undefined) ?? '';
    try {
      const pair = await this.auth.refresh(raw, fingerprint);
      setAuthCookies(res, this.cookiePolicy, pair);
      return { csrf_token: pair.csrfToken };
    } catch (err) {
      clearAuthCookies(res, this.cookiePolicy);
      throw err;
    }
  }

  @Post('logout')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(204)
  async logout(
    @Principal() principal: VerifiedPrincipal,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.auth.logout(principal);
    clearAuthCookies(res, this.cookiePolicy);
  }

  @Get('sessions')
  @UseGuards(AuthGuard)
  async listSessions(
    @Principal() principal: VerifiedPrincipal,
  ): Promise<{ sessions: Array<{ session_id: string; current: boolean; created_at: string; ip: string }> }> {
    const ids = await this.sessions.listSessionIds(principal.userId);
    const sessions = [];
    for (const id of ids) {
      const record = await this.sessions.get(id);
      if (!record) continue;
      sessions.push({
        session_id: id,
        current: id === principal.sessionId,
        created_at: new Date(record.createdAt * 1000).toISOString(),
        ip: record.ip,
      });
    }
    return { sessions };
  }

  @Delete('sessions')
  @UseGuards(AuthGuard, CsrfGuard)
  @HttpCode(204)
  async revokeOthers(@Principal() principal: VerifiedPrincipal): Promise<void> {
    await this.auth.revokeOtherSessions(principal);
  }

  /**
   * Traefik ForwardAuth endpoint. 2xx allows the proxied request; the
   * whitelisted X-User-* headers become the caller identity downstream.
   * Enforces gateway-level CSRF for mutating methods (double-submit:
   * X-CSRF-Token header must match the session's secret).
   */
  @Get('verify')
  @Head('verify')
  async verify(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<void> {
    const token = req.cookies?.[this.cookiePolicy.accessName] as string | undefined;
    if (!token) throw new UnauthorizedException('not authenticated');
    const principal = await this.auth.verify(token);

    // A password-only session for an MFA-enrolled user gets no further than this.
    // It stays valid for /auth/* (which bypasses ForwardAuth) so the user can
    // finish the challenge or log out, but it reaches no protected route.
    if (principal.mfaPending) {
      throw new UnauthorizedException('step-up required');
    }

    const method = (req.headers['x-forwarded-method'] as string | undefined)?.toUpperCase() ?? 'GET';
    if (!SAFE_METHODS.has(method)) {
      const headerToken = req.headers['x-csrf-token'] as string | undefined;
      if (!headerToken) throw new ForbiddenException('missing CSRF token');
      this.auth.verifyCsrf(headerToken, principal.csrfSecret);
    }

    res.setHeader('X-User-Id', principal.userId);
    res.setHeader('X-User-Roles', principal.roles.join(','));
    res.setHeader('X-Session-Id', principal.sessionId);
    // Authentication strength, so services can gate high-risk operations. Traefik
    // overwrites these from this response, so a client cannot forge them.
    res.setHeader('X-Auth-Amr', principal.amr.join(','));
    res.setHeader('X-Auth-Time', String(principal.authTime));

    // The gateway assertion is what makes the headers above trustworthy on the
    // internal network, not just at the edge: a signed statement, verifiable by
    // every service through the JWKS, that this identity came from ForwardAuth.
    // Without it a peer container could forge X-User-Id and impersonate a user.
    res.setHeader(
      'X-Gateway-Assertion',
      await this.gatewayAssertion.issue({
        sub: principal.userId,
        roles: principal.roles,
        sid: principal.sessionId,
        amr: principal.amr,
        auth_time: principal.authTime,
      }),
    );
  }
}
