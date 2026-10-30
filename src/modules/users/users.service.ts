import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import { CreateUserDto, UserResponseDto } from './dto';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new ConflictException(
        'El correo electrónico ya se encuentra registrado.',
      );
    }

    return this.prisma.user.create({
      data: {
        email: createUserDto.email.toLowerCase().trim(),
        passwordHash: createUserDto.passwordHash,
      },
    });
  }

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });
  }

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('Usuario no encontrado.');
    }

    return user;
  }

  async getProfile(id: string): Promise<UserResponseDto> {
    const user = await this.findById(id);

    return {
      id: user.id,
      email: user.email,
      isTwoFactorEnabled: user.isTwoFactorEnabled,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}

