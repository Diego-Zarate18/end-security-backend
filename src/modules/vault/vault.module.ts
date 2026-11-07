import { Module } from '@nestjs/common';
import { AccountModule } from '../account/account.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { VaultController } from './controllers';
import { VaultService } from './services';

@Module({
  imports: [AuditModule, AuthModule, UsersModule, AccountModule],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
