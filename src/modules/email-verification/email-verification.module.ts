import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { MailModule } from '../mail/mail.module';
import { EmailCodeService } from './services';

/**
 * Códigos de verificación de correo. Sin controller propio: los endpoints
 * /auth/email/verify/* viven en AuthController, que lo importa.
 */
@Module({
  imports: [AuditModule, MailModule],
  providers: [EmailCodeService],
  exports: [EmailCodeService],
})
export class EmailVerificationModule {}
