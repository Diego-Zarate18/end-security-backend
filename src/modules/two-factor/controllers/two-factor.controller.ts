import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
  Public,
} from '../../../common/decorators';
import { AuthResponseDto } from '../../auth/dto';
import type { AuthenticatedUser } from '../../auth/strategies';
import {
  ActivateTwoFactorDto,
  ReauthDto,
  RecoveryCodesDto,
  SensitiveTwoFactorDto,
  TwoFactorSetupDto,
  TwoFactorStatusDto,
  VerifyTwoFactorDto,
} from '../dto';
import { TwoFactorService } from '../services';

@Controller('auth/2fa')
export class TwoFactorController {
  constructor(private readonly service: TwoFactorService) {}

  @Get()
  status(@CurrentUser('id') userId: string): Promise<TwoFactorStatusDto> {
    return this.service.status(userId);
  }

  /** Genera el secreto y el QR. Requiere la contraseña maestra. */
  @HttpCode(HttpStatus.OK)
  @Post('setup')
  setup(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: ReauthDto,
  ): Promise<TwoFactorSetupDto> {
    return this.service.setup(this.actor(user, client), dto.authHash);
  }

  /** Confirma el primer código y entrega los códigos de recuperación (una sola vez). */
  @HttpCode(HttpStatus.OK)
  @Post('activate')
  activate(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: ActivateTwoFactorDto,
  ): Promise<RecoveryCodesDto> {
    return this.service.activate(this.actor(user, client), dto.code);
  }

  /** Segundo paso del login: challengeToken + código TOTP o de recuperación. */
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('verify')
  verify(
    @Body() dto: VerifyTwoFactorDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<AuthResponseDto> {
    return this.service.verifyLogin(dto, client);
  }

  @HttpCode(HttpStatus.OK)
  @Post('disable')
  disable(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: SensitiveTwoFactorDto,
  ): Promise<TwoFactorStatusDto> {
    return this.service.disable(this.actor(user, client), dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('recovery-codes')
  regenerateRecoveryCodes(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: SensitiveTwoFactorDto,
  ): Promise<RecoveryCodesDto> {
    return this.service.regenerateRecoveryCodes(this.actor(user, client), dto);
  }

  private actor(user: AuthenticatedUser, client: ClientInfoData) {
    return { userId: user.id, sessionId: user.sessionId, client };
  }
}
