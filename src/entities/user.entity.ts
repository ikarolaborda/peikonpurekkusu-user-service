import { defineEntity, type InferEntity } from '@mikro-orm/core';
import { randomUUID } from 'node:crypto';

export enum KycStatus {
  PENDING = 'pending',
  VERIFIED = 'verified',
  REJECTED = 'rejected',
}

export enum UserStatus {
  ACTIVE = 'active',
  FROZEN = 'frozen',
}

export const User = defineEntity({
  name: 'User',
  tableName: 'users',
  properties: (p) => ({
    id: p.uuid().primary().onCreate(() => randomUUID()),
    email: p.string().unique(),
    /** Argon2id PHC string — hidden from every serialized read model. */
    passwordHash: p.string().hidden(),
    firstName: p.string(),
    lastName: p.string(),
    kycStatus: p.string().$type<KycStatus>().default(KycStatus.PENDING),
    status: p.string().$type<UserStatus>().default(UserStatus.ACTIVE),
    mfaEnrolled: p.boolean().default(false),
    roles: p.json().$type<string[]>().onCreate(() => ['customer']),
    createdAt: p.datetime().onCreate(() => new Date()),
    updatedAt: p.datetime().onCreate(() => new Date()).onUpdate(() => new Date()),
  }),
});

export type UserEntity = InferEntity<typeof User>;
