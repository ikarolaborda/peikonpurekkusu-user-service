import type { CookieOptions, Response } from 'express';
import type { CookiePair } from './auth.service.js';

/**
 * Cookie policy (the browser-side half of theft protection):
 * - access  cookie  Path=/             SameSite=Lax    (top-level 3DS-style returns still work)
 * - refresh cookie  Path=/auth/refresh SameSite=Strict (only ever sent to the rotation endpoint)
 * Both httpOnly. In TLS deployments names are __Host-at / __Secure-rt with
 * Secure set (COOKIE_SECURE=true; __Host- forbids a scoped Path, hence the
 * __Secure- prefix on refresh). The plain-HTTP dev compose uses at/rt without
 * Secure because non-browser clients reject prefixed cookies over http.
 */
export interface CookiePolicy {
  accessName: string;
  refreshName: string;
  secure: boolean;
}

const accessBase = (p: CookiePolicy): CookieOptions => ({
  httpOnly: true,
  secure: p.secure,
  sameSite: 'lax',
  path: '/',
});

const refreshBase = (p: CookiePolicy): CookieOptions => ({
  httpOnly: true,
  secure: p.secure,
  sameSite: 'strict',
  path: '/auth/refresh',
});

export function setAuthCookies(res: Response, policy: CookiePolicy, pair: CookiePair): void {
  res.cookie(policy.accessName, pair.accessToken, {
    ...accessBase(policy),
    expires: pair.accessExpiresAt,
  });
  res.cookie(policy.refreshName, pair.refreshToken, {
    ...refreshBase(policy),
    expires: pair.refreshExpiresAt,
  });
}

export function clearAuthCookies(res: Response, policy: CookiePolicy): void {
  res.clearCookie(policy.accessName, accessBase(policy));
  res.clearCookie(policy.refreshName, refreshBase(policy));
}
