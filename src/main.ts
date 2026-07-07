import { MikroORM } from '@mikro-orm/postgresql';
import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const logger = new Logger('bootstrap');

  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  app.enableShutdownHooks();
  // Behind Traefik on the edge network — trust exactly one proxy hop for req.ip.
  app.getHttpAdapter().getInstance().set('trust proxy', 1);

  // Migrations at boot: goose-style embedded flow; MikroORM's Migrator runs
  // each migration transactionally, allOrNothing across the batch.
  const orm = app.get(MikroORM);
  await orm.migrator.up();
  logger.log('migrations applied');

  await app.listen(8080, '0.0.0.0');
  logger.log('user-service listening on :8080');
}

void bootstrap();
