import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
  Public,
} from '../../../common/decorators';
import { AuthService, LoginResult } from '../services/auth.service';
import {
  AuthResponseDto,
  EmailVerificationRequiredDto,
  LoginDto,
  PreloginDto,
  PreloginResponseDto,
  RefreshTokenDto,
  RegisterDto,
  ResendEmailCodeDto,
  TokenPairDto,
  TwoFactorChallengeDto,
  VerifyEmailDto,
} from '../dto';
import type { AuthenticatedUser } from '../strategies';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('prelogin')
  prelogin(@Body() dto: PreloginDto): Promise<PreloginResponseDto> {
    return this.authService.prelogin(dto);
  }

  @Public()
  @Post('register')
  register(
    @Body() dto: RegisterDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    return this.authService.register(dto, client);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(
    @Body() dto: LoginDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<LoginResult> {
    return this.authService.login(dto, client);
  }

  /** Confirma el correo con el código e inicia la sesión. */
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('email/verify/confirm')
  verifyEmail(
    @Body() dto: VerifyEmailDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<AuthResponseDto | TwoFactorChallengeDto> {
    return this.authService.verifyEmail(dto, client);
  }

  @Public()
  @HttpCode(HttpStatus.ACCEPTED)
  @Post('email/verify/resend')
  resendEmailCode(
    @Body() dto: ResendEmailCodeDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    return this.authService.resendEmailCode(dto, client);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refresh(
    @Body() dto: RefreshTokenDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<TokenPairDto> {
    return this.authService.refresh(dto.refreshToken, client);
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('logout')
  logout(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
  ): Promise<void> {
    return this.authService.logout(user.id, user.sessionId, client);
  }
}
