import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { EmailVerificationModule } from '../email-verification/email-verification.module';
import { MailModule } from '../mail/mail.module';
import { TwoFactorModule } from '../two-factor/two-factor.module';
import { UsersModule } from '../users/users.module';
import { AccountController } from './controllers';
import { AccountService, ReauthService } from './services';

/**
 * Cambiar la contraseña maestra y borrar la cuenta. Exporta ReauthService para
 * otras operaciones irreversibles (rotar la clave de la bóveda).
 */
@Module({
  imports: [
    UsersModule,
    TwoFactorModule,
    AuditModule,
    MailModule,
    EmailVerificationModule,
  ],
  controllers: [AccountController],
  providers: [AccountService, ReauthService],
  exports: [ReauthService],
})
export class AccountModule {}
