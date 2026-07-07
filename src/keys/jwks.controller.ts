import { Controller, Get, Header } from '@nestjs/common';
import { KeysService } from './keys.service.js';

@Controller('.well-known')
export class JwksController {
  constructor(private readonly keys: KeysService) {}

  /** Public verification keys. Consumers cache and refetch on unknown kid. */
  @Get('jwks.json')
  @Header('Cache-Control', 'public, max-age=600')
  jwks(): { keys: unknown[] } {
    return this.keys.jwks();
  }
}
