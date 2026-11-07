import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuditModule } from '../audit/audit.module';
import { EmailVerificationModule } from '../email-verification/email-verification.module';
import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';
import { AuthController, SessionsController } from './controllers';
import { JwtAuthGuard } from './guards';
import { AuthService, SessionsService, TokenService } from './services';
import { JwtStrategy } from './strategies';

@Module({
  imports: [
    UsersModule,
    AuditModule,
    EmailVerificationModule,
    MailModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.getOrThrow<string>('JWT_SECRET'),
        signOptions: { algorithm: 'HS256' },
        verifyOptions: { algorithms: ['HS256'] },
      }),
    }),
  ],
  controllers: [AuthController, SessionsController],
  providers: [
    AuthService,
    TokenService,
    SessionsService,
    JwtStrategy,
    JwtAuthGuard,
  ],
  exports: [
    AuthService,
    TokenService,
    SessionsService,
    JwtAuthGuard,
    JwtModule,
  ],
})
export class AuthModule {}
