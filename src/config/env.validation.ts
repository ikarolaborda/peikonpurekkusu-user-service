import { plainToInstance } from 'class-transformer';
import { IsInt, IsString, Min, validateSync } from 'class-validator';

/**
 * Fail-fast environment contract. Names match the repo-root .env.example —
 * compose passes them through; nothing else configures this service.
 */
export class Env {
  @IsString() USERS_DB_HOST: string = 'users-db';
  @IsInt() @Min(1) USERS_DB_PORT: number = 5432;
  @IsString() USERS_DB_USER: string;
  @IsString() USERS_DB_PASSWORD: string;
  @IsString() USERS_DB_NAME: string;

  @IsString() REDIS_SESSION_HOST: string = 'redis-session';
  @IsInt() @Min(1) REDIS_SESSION_PORT: number = 6379;
  @IsString() REDIS_SESSION_PASSWORD: string;

  @IsString() KAFKA_BOOTSTRAP_SERVERS: string = 'kafka:19092';
  @IsString() SCHEMA_REGISTRY_URL: string = 'http://apicurio-registry:8080/apis/ccompat/v7';

  @IsString() JWT_ISSUER: string;
  @IsString() JWT_AUDIENCE: string;
  @IsInt() @Min(60) ACCESS_TOKEN_TTL: number = 600;
  @IsInt() @Min(3600) REFRESH_TOKEN_TTL: number = 1209600;

  @IsString() JWT_PRIVATE_KEY_PATH: string = '/secrets/jwt-es256-private.pem';
  @IsString() JWT_KID_PATH: string = '/secrets/jwt-es256.kid';

  /** Grace window for parallel-tab refresh races (ms). Outside it, reuse = theft. */
  @IsInt() @Min(0) REFRESH_REUSE_GRACE_MS: number = 10_000;

  @IsString() COOKIE_ACCESS_NAME: string = '__Host-at';
  @IsString() COOKIE_REFRESH_NAME: string = '__Secure-rt';
  /**
   * 'true' in any TLS deployment (mandatory with the __Host-/__Secure- names).
   * The dev compose runs plain HTTP behind Traefik, where non-browser clients
   * (curl, smoke tests) reject Secure/prefixed cookies — dev uses at/rt+false.
   * Kept as a string: implicit class-transformer boolean conversion treats
   * the string "false" as truthy.
   */
  @IsString() COOKIE_SECURE: string = 'true';
}

export function validateEnv(raw: Record<string, unknown>): Env {
  const env = plainToInstance(Env, raw, {
    enableImplicitConversion: true,
    exposeDefaultValues: true,
    excludeExtraneousValues: false,
  });
  const errors = validateSync(env, { whitelist: true });
  if (errors.length > 0) {
    throw new Error(
      `user-service env validation failed:\n${errors
        .map((e) => Object.values(e.constraints ?? {}).join(', '))
        .join('\n')}`,
    );
  }
  return env;
}
