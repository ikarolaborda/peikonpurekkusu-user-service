import { Migration } from '@mikro-orm/migrations';

export class Migration20260707000001_initial extends Migration {
  override async up(): Promise<void> {
    this.addSql(`
      create table "users" (
        "id" uuid primary key,
        "email" varchar(255) not null,
        "password_hash" varchar(255) not null,
        "first_name" varchar(255) not null,
        "last_name" varchar(255) not null,
        "kyc_status" text check ("kyc_status" in ('pending','verified','rejected')) not null default 'pending',
        "status" text check ("status" in ('active','frozen')) not null default 'active',
        "mfa_enrolled" boolean not null default false,
        "roles" jsonb not null default '["customer"]'::jsonb,
        "created_at" timestamptz not null,
        "updated_at" timestamptz not null,
        constraint "users_email_unique" unique ("email")
      );
    `);

    this.addSql(`
      create table "refresh_tokens" (
        "id" uuid primary key,
        "user_id" uuid not null references "users" ("id") on delete cascade,
        "family_id" uuid not null,
        "generation" int not null,
        "token_hash" varchar(64) not null,
        "session_id" varchar(255) not null,
        "device_fingerprint_hash" varchar(64) null,
        "expires_at" timestamptz not null,
        "consumed_at" timestamptz null,
        "revoked_at" timestamptz null,
        "created_at" timestamptz not null,
        constraint "refresh_tokens_token_hash_unique" unique ("token_hash")
      );
      create index "refresh_tokens_family_id_index" on "refresh_tokens" ("family_id");
    `);

    this.addSql(`
      create table "outbox" (
        "id" uuid primary key,
        "aggregatetype" varchar(255) not null,
        "aggregateid" varchar(255) not null,
        "type" varchar(255) not null,
        "payload" jsonb not null,
        "created_at" timestamptz not null,
        "processed_at" timestamptz null
      );
      create index "outbox_unprocessed_idx" on "outbox" ("id") where "processed_at" is null;
    `);
  }

  override async down(): Promise<void> {
    this.addSql('drop table if exists "outbox";');
    this.addSql('drop table if exists "refresh_tokens";');
    this.addSql('drop table if exists "users";');
  }
}
