import { Body, Controller, Get, Put } from '@nestjs/common';
import { CurrentUser } from '../../common/decorators';
import { SyncVaultDto, VaultResponseDto } from './dto';
import { VaultService } from './vault.service';

@Controller('vault')
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  @Get()
  async getVault(
    @CurrentUser('id') userId: string,
  ): Promise<VaultResponseDto> {
    return this.vaultService.getVault(userId);
  }

  @Put()
  async syncVault(
    @CurrentUser('id') userId: string,
    @Body() syncVaultDto: SyncVaultDto,
  ): Promise<VaultResponseDto> {
    return this.vaultService.syncVault(userId, syncVaultDto);
  }
}

