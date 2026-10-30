import { Controller, Get } from '@nestjs/common';
import { CurrentUser } from '../../common/decorators';
import { UserResponseDto } from './dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  async getProfile(
    @CurrentUser('id') userId: string,
  ): Promise<UserResponseDto> {
    return this.usersService.getProfile(userId);
  }
}