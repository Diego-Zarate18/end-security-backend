import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
} from '../../../common/decorators';
import type { AuthenticatedUser } from '../../auth/strategies';
import { UserResponseDto } from '../../users/dto';
import {
  CodeSentDto,
  ConfirmEmailCodeDto,
  RequestEmailChangeDto,
} from '../dto';
import { EmailVerificationService } from '../services';

@Controller('auth/email')
export class EmailVerificationController {
  constructor(private readonly service: EmailVerificationService) {}

  /** Envía un código al correo actual de la cuenta. */
  @HttpCode(HttpStatus.ACCEPTED)
  @Post('verify/request')
  requestVerification(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
  ): Promise<CodeSentDto> {
    return this.service.requestVerification(this.actor(user, client));
  }

  @HttpCode(HttpStatus.OK)
  @Post('verify/confirm')
  confirmVerification(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: ConfirmEmailCodeDto,
  ): Promise<UserResponseDto> {
    return this.service.confirmVerification(this.actor(user, client), dto.code);
  }

  /** Requiere la contraseña maestra; el código llega al correo nuevo. */
  @HttpCode(HttpStatus.ACCEPTED)
  @Post('change/request')
  requestEmailChange(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: RequestEmailChangeDto,
  ): Promise<CodeSentDto> {
    return this.service.requestEmailChange(this.actor(user, client), dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('change/confirm')
  confirmEmailChange(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: ConfirmEmailCodeDto,
  ): Promise<UserResponseDto> {
    return this.service.confirmEmailChange(this.actor(user, client), dto.code);
  }

  private actor(user: AuthenticatedUser, client: ClientInfoData) {
    return { userId: user.id, sessionId: user.sessionId, client };
  }
}
