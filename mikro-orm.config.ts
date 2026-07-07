import { Migrator } from '@mikro-orm/migrations';
import { defineConfig } from '@mikro-orm/postgresql';
import { OutboxEvent } from './src/entities/outbox-event.entity.js';
import { RefreshToken } from './src/entities/refresh-token.entity.js';
import { User } from './src/entities/user.entity.js';

export default defineConfig({
  host: process.env.USERS_DB_HOST ?? 'users-db',
  port: Number(process.env.USERS_DB_PORT ?? 5432),
  user: process.env.USERS_DB_USER,
  password: process.env.USERS_DB_PASSWORD,
  dbName: process.env.USERS_DB_NAME,
  entities: [User, RefreshToken, OutboxEvent],
  extensions: [Migrator],
  migrations: {
    path: 'dist/src/migrations',
    pathTs: 'src/migrations',
    glob: '!(*.d).{js,ts}',
    transactional: true,
    allOrNothing: true,
    snapshot: false,
  },
  forceUtcTimezone: true,
});
