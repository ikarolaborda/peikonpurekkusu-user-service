import {
  Body,
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

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

@Controller('auth')
export class AuthController {
  private readonly cookiePolicy: { accessName: string; refreshName: string; secure: boolean };

  constructor(
    private readonly auth: AuthService,
    private readonly mfa: MfaService,
    private readonly sessions: SessionsService,
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
  @UseGuards(AuthGuard)
  @HttpCode(200)
  async mfaVerify(
    @Body() dto: MfaVerifyDto,
    @Principal() principal: VerifiedPrincipal,
  ): Promise<{ elevated: boolean }> {
    const ok = await this.mfa.verify(principal.sessionId, dto.code);
    if (!ok) throw new UnauthorizedException('invalid code');
    return { elevated: true };
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

    const method = (req.headers['x-forwarded-method'] as string | undefined)?.toUpperCase() ?? 'GET';
    if (!SAFE_METHODS.has(method)) {
      const headerToken = req.headers['x-csrf-token'] as string | undefined;
      if (!headerToken) throw new ForbiddenException('missing CSRF token');
      this.auth.verifyCsrf(headerToken, principal.csrfSecret);
    }

    res.setHeader('X-User-Id', principal.userId);
    res.setHeader('X-User-Roles', principal.roles.join(','));
    res.setHeader('X-Session-Id', principal.sessionId);
  }
}
