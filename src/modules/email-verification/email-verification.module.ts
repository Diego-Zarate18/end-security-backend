import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';
import { EmailVerificationController } from './controllers';
import { EmailCodeService, EmailVerificationService } from './services';

/** No importa AuthModule: AuthModule lo importa a él para el login con correo verificado. */
@Module({
  imports: [UsersModule, AuditModule, MailModule],
  controllers: [EmailVerificationController],
  providers: [EmailCodeService, EmailVerificationService],
  exports: [EmailCodeService],
})
export class EmailVerificationModule {}
