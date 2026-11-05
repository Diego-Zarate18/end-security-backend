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

/** Cambio de correo. La verificación inicial está en /auth/email/verify/* (AuthController). */
@Controller('auth/email/change')
export class EmailVerificationController {
  constructor(private readonly service: EmailVerificationService) {}

  /** Requiere la contraseña maestra; el código llega al correo nuevo. */
  @HttpCode(HttpStatus.ACCEPTED)
  @Post('request')
  requestEmailChange(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: RequestEmailChangeDto,
  ): Promise<CodeSentDto> {
    return this.service.requestEmailChange(this.actor(user, client), dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('confirm')
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
