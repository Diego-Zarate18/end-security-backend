import { Controller, Get, Query } from '@nestjs/common';
import { CurrentUser } from '../../../common/decorators';
import {
  AuditChainReportDto,
  AuditLogPageDto,
  QueryAuditLogsDto,
} from '../dto';
import { AuditService } from '../services';

@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  /** Historial de seguridad del propio usuario, del más reciente al más viejo. */
  @Get()
  list(
    @CurrentUser('id') userId: string,
    @Query() query: QueryAuditLogsDto,
  ): Promise<AuditLogPageDto> {
    return this.auditService.list(userId, query.limit ?? 50, query.before);
  }

  /** Recalcula la cadena de HMAC y reporta el primer eslabón alterado. */
  @Get('verify')
  verify(@CurrentUser('id') userId: string): Promise<AuditChainReportDto> {
    return this.auditService.verify(userId);
  }
}
