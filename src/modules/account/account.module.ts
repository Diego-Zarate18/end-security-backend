import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { MailModule } from '../mail/mail.module';
import { TwoFactorModule } from '../two-factor/two-factor.module';
import { UsersModule } from '../users/users.module';
import { AccountController } from './controllers';
import { AccountService } from './services';

/** Cambiar la contraseña maestra y borrar la cuenta. */
@Module({
  imports: [UsersModule, TwoFactorModule, AuditModule, MailModule],
  controllers: [AccountController],
  providers: [AccountService],
})
export class AccountModule {}
