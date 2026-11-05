import { Module } from '@nestjs/common';
import { AuditController } from './controllers';
import { AuditService } from './services';

@Module({
  controllers: [AuditController],
  providers: [AuditService],
  exports: [AuditService],
})
export class AuditModule {}
