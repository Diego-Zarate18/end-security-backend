import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { VaultController } from './controllers';
import { VaultService } from './services';

@Module({
  imports: [AuditModule],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
