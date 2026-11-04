import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
} from '@nestjs/common';
import { CurrentUser } from '../../common/decorators';
import {
  PushVaultChangesDto,
  SyncQueryDto,
  VaultPushResponseDto,
  VaultSyncResponseDto,
} from './dto';
import { VaultService } from './vault.service';

@Controller('vault')
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  /** Cambios posteriores a la revisión `since` (o la bóveda completa). */
  @Get('sync')
  getChanges(
    @CurrentUser('id') userId: string,
    @Query() query: SyncQueryDto,
  ): Promise<VaultSyncResponseDto> {
    return this.vaultService.getChanges(userId, query.since ?? 0);
  }

  /** Aplica un lote de cambios de forma atómica (todo o nada). */
  @HttpCode(HttpStatus.OK)
  @Post('sync')
  pushChanges(
    @CurrentUser('id') userId: string,
    @Body() dto: PushVaultChangesDto,
  ): Promise<VaultPushResponseDto> {
    return this.vaultService.pushChanges(userId, dto);
  }
}
