import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { CurrentUser, Public } from '../../common/decorators';
import { AuthService } from './auth.service';
import {
  AuthResponseDto,
  LoginDto,
  PreloginDto,
  PreloginResponseDto,
  RefreshTokenDto,
  RegisterDto,
  TokenPairDto,
  TwoFactorChallengeDto,
} from './dto';
import type { AuthenticatedUser } from './strategies';

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
  register(@Body() dto: RegisterDto): Promise<AuthResponseDto> {
    return this.authService.register(dto);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(
    @Body() dto: LoginDto,
  ): Promise<AuthResponseDto | TwoFactorChallengeDto> {
    return this.authService.login(dto);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refresh(@Body() dto: RefreshTokenDto): Promise<TokenPairDto> {
    return this.authService.refresh(dto.refreshToken);
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('logout')
  logout(@CurrentUser() user: AuthenticatedUser): Promise<void> {
    return this.authService.logout(user.id, user.sessionId);
  }
}
