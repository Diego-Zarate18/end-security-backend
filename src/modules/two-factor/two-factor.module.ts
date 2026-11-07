import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { TwoFactorController } from './controllers';
import { TotpSecretService, TwoFactorService } from './services';

@Module({
  imports: [AuthModule, UsersModule, AuditModule],
  controllers: [TwoFactorController],
  providers: [TwoFactorService, TotpSecretService],
  exports: [TwoFactorService],
})
export class TwoFactorModule {}
