import {
  Body,
  Controller,
  Delete,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
} from '../../../common/decorators';
import type { AuthenticatedUser } from '../../auth/strategies';
import {
  ChangeMasterPasswordDto,
  DeleteAccountDto,
  PasswordChangedDto,
} from '../dto';
import { AccountService } from '../services';

@Controller()
export class AccountController {
  constructor(private readonly accountService: AccountService) {}

  /** Bajo /auth para compartir el límite estricto de intentos. */
  @HttpCode(HttpStatus.OK)
  @Post('auth/password')
  changeMasterPassword(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: ChangeMasterPasswordDto,
  ): Promise<PasswordChangedDto> {
    return this.accountService.changeMasterPassword(
      this.actor(user, client),
      dto,
    );
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete('users/me')
  deleteAccount(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: DeleteAccountDto,
  ): Promise<void> {
    return this.accountService.deleteAccount(this.actor(user, client), dto);
  }

  private actor(user: AuthenticatedUser, client: ClientInfoData) {
    return { userId: user.id, sessionId: user.sessionId, client };
  }
}
