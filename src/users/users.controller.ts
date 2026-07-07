import { Controller, Get, Headers, NotFoundException } from '@nestjs/common';
import { EntityManager } from '@mikro-orm/postgresql';
import { User } from '../entities/user.entity.js';

/**
 * Routed through Traefik's jwt-auth ForwardAuth middleware — identity arrives
 * as X-User-Id, which is only trustworthy because this container is reachable
 * exclusively through the gateway on the edge network.
 */
@Controller('users')
export class UsersController {
  constructor(private readonly em: EntityManager) {}

  @Get('me')
  async me(@Headers('x-user-id') userId: string): Promise<{
    user_id: string;
    email: string;
    first_name: string;
    last_name: string;
    kyc_status: string;
    mfa_enrolled: boolean;
    created_at: string;
  }> {
    const user = await this.em.fork().findOne(User, { id: userId });
    if (!user) throw new NotFoundException('user not found');
    return {
      user_id: user.id,
      email: user.email,
      first_name: user.firstName,
      last_name: user.lastName,
      kyc_status: user.kycStatus,
      mfa_enrolled: user.mfaEnrolled,
      created_at: user.createdAt.toISOString(),
    };
  }
}
