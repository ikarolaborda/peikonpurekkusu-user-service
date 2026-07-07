import { defineEntity, type InferEntity } from '@mikro-orm/core';
import { randomUUID } from 'node:crypto';

/**
 * One row per issued refresh token. The raw token never touches the database —
 * only its SHA-256 hash. Rotation consumes a row (consumedAt) and issues the
 * next generation in the same family; reuse of a consumed row outside the
 * grace window revokes the whole family (theft signal, RFC 9700).
 * The users(id) FK lives in the migration; queries key on tokenHash/familyId.
 */
export const RefreshToken = defineEntity({
  name: 'RefreshToken',
  tableName: 'refresh_tokens',
  properties: (p) => ({
    id: p.uuid().primary().onCreate(() => randomUUID()),
    userId: p.uuid().index(),
    familyId: p.uuid().index(),
    generation: p.integer(),
    tokenHash: p.string().length(64).unique(),
    sessionId: p.string(),
    deviceFingerprintHash: p.string().length(64).nullable(),
    expiresAt: p.datetime(),
    consumedAt: p.datetime().nullable(),
    revokedAt: p.datetime().nullable(),
    createdAt: p.datetime().onCreate(() => new Date()),
  }),
});

export type RefreshTokenEntity = InferEntity<typeof RefreshToken>;
