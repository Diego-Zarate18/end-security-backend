import { Body, Controller, Get, Patch } from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
} from '../../../common/decorators';
import type { AuthenticatedUser } from '../../auth/strategies';
import { UpdateProfileDto, UserResponseDto } from '../dto';
import { UsersService } from '../services/users.service';

/** Borrar la cuenta (DELETE /users/me) está en AccountController. */
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  getProfile(@CurrentUser('id') userId: string): Promise<UserResponseDto> {
    return this.usersService.getProfile(userId);
  }

  @Patch('me')
  updateProfile(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Body() dto: UpdateProfileDto,
  ): Promise<UserResponseDto> {
    return this.usersService.updateProfile(user, dto, client);
  }
}
