import { Logger } from '@nestjs/common';

/**
 * Strategy port for MFA challenge delivery. Real deployments plug in SMS/TOTP
 * providers; the dev transports log the code and are deliberately boring.
 */
export interface MfaChannelStrategy {
  readonly name: string;
  deliver(sessionId: string, code: string): Promise<void>;
}

export class EmailMockStrategy implements MfaChannelStrategy {
  readonly name = 'email';
  private readonly logger = new Logger('MfaEmailMock');

  async deliver(sessionId: string, code: string): Promise<void> {
    // Dev transport: the smoke test and manual login read the code from logs.
    this.logger.log(`MFA code for session ${sessionId.slice(0, 8)}…: ${code}`);
  }
}

export class TotpMockStrategy implements MfaChannelStrategy {
  readonly name = 'totp';
  private readonly logger = new Logger('MfaTotpMock');

  async deliver(sessionId: string, code: string): Promise<void> {
    this.logger.log(`TOTP expected for session ${sessionId.slice(0, 8)}…: ${code}`);
  }
}
