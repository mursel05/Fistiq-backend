import { FastifyReply } from 'fastify';
import {
  Injectable,
  InternalServerErrorException,
  Logger,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { TokenService } from 'src/modules/auth/token.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import { EmailService } from 'src/shared/email/email.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { MutationResponse } from 'src/common/dto/mutation-response.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private usersRepo: Repository<User>,
    private tokenService: TokenService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {}

  private configureCookies(
    response: FastifyReply,
    tokens: { accessToken: string; refreshToken: string },
  ): void {
    const isProduction =
      this.configService.get<string>('app.nodeEnv') === 'production';
    const cookieOptions = isProduction
      ? {
          httpOnly: true,
          sameSite: 'none' as const,
          secure: true,
        }
      : {};
    response.setCookie('access_token', tokens.accessToken, {
      ...cookieOptions,
      maxAge: Number(
        this.configService.get<string>('auth.accessTokenExpiryMs'),
      ),
    });
    response.setCookie('refresh_token', tokens.refreshToken, {
      ...cookieOptions,
      maxAge: Number(
        this.configService.get<string>('auth.refreshTokenExpiryMs'),
      ),
    });
  }

  private async generateResetCode(): Promise<number> {
    try {
      const resetCode = crypto.randomBytes(4).readUInt32BE(0) % 1000000;
      const existingUser = await this.usersRepo.findOne({
        where: { resetCode },
      });

      if (existingUser) {
        return this.generateResetCode();
      }

      return resetCode;
    } catch (error) {
      this.logger.error('Error generating reset code', String(error));
      throw new InternalServerErrorException('Failed to generate reset code');
    }
  }

  async register(
    registerDto: RegisterDto,
    response: FastifyReply,
  ): Promise<MutationResponse> {
    try {
      this.logger.debug(`Registration attempt for email: ${registerDto.email}`);

      const existingUser = await this.usersRepo.findOne({
        where: { email: registerDto.email },
      });

      if (existingUser) {
        this.logger.warn(
          `Registration failed: Email already exists - ${registerDto.email}`,
        );
        throw new ConflictException('Email already in use');
      }

      const hashedPassword: string = await bcrypt.hash(
        registerDto.password,
        10,
      );

      const user = await this.usersRepo.save({
        ...registerDto,
        password: hashedPassword,
      });

      const tokens = await this.tokenService.generateTokens({
        sub: user.id,
      });

      this.configureCookies(response, tokens);

      this.logger.log(
        `User registered successfully: ${user.id} (${user.email})`,
      );

      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }

      this.logger.error(
        `Registration failed for ${registerDto.email}`,
        String(error),
      );
      throw new InternalServerErrorException('Failed to register user');
    }
  }

  async login(
    loginDto: LoginDto,
    response: FastifyReply,
  ): Promise<MutationResponse> {
    try {
      this.logger.debug(`Login attempt for email: ${loginDto.email}`);

      const user = await this.usersRepo.findOne({
        where: { email: loginDto.email },
      });

      if (!user) {
        this.logger.warn(`Login failed: User not found - ${loginDto.email}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      if (user.isBanned) {
        this.logger.warn(
          `Login failed: Banned user attempted to login - ${user.id}`,
        );
        throw new ForbiddenException(
          'Account is banned. Please contact support.',
        );
      }

      const isPasswordValid = await bcrypt.compare(
        loginDto.password,
        user.password,
      );

      if (!isPasswordValid) {
        this.logger.warn(`Login failed: Invalid password - ${user.id}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      user.lastLogin = new Date();
      await this.usersRepo.save(user);

      const tokens = await this.tokenService.generateTokens({
        sub: user.id,
      });

      this.configureCookies(response, tokens);

      this.logger.log(`User logged in successfully: ${user.id}`);

      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof ForbiddenException
      ) {
        throw error;
      }

      this.logger.error(`Login failed for ${loginDto.email}`, String(error));
      throw new InternalServerErrorException('Failed to process login');
    }
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<MutationResponse> {
    try {
      this.logger.debug(
        `Forgot password request for: ${forgotPasswordDto.email}`,
      );

      const user = await this.usersRepo.findOne({
        where: { email: forgotPasswordDto.email },
      });

      if (!user) {
        this.logger.warn(
          `Forgot password: User not found - ${forgotPasswordDto.email}`,
        );
        throw new UnauthorizedException('Invalid credentials');
      }

      if (user.isBanned) {
        this.logger.warn(`Forgot password: Banned user attempted - ${user.id}`);
        throw new ForbiddenException(
          'Account is banned. Please contact support.',
        );
      }

      if (user.resetCodeExpiry && user.resetCodeExpiry > new Date()) {
        this.logger.warn(
          `Forgot password: Reset code already sent - ${user.id}`,
        );
        throw new BadRequestException(
          'A reset code has already been sent. Please check your email or wait before requesting again.',
        );
      }

      const resetCode = await this.generateResetCode();
      user.resetCode = resetCode;
      user.resetCodeExpiry = new Date(Date.now() + 12 * 60 * 1000);
      await this.usersRepo.save(user);

      void this.emailService.sendResetCode(forgotPasswordDto.email, resetCode);

      this.logger.log(`Password reset code generated for user: ${user.id}`);
      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      this.logger.error(
        `Failed to process forgot password for ${forgotPasswordDto.email}`,
        error,
      );
      throw new InternalServerErrorException(
        'Failed to process password reset request',
      );
    }
  }

  async verifyCode(code: number): Promise<MutationResponse> {
    try {
      this.logger.debug(`Verifying reset code: ${code}`);
      const user = await this.usersRepo.findOne({
        where: { resetCode: code },
      });

      if (!user) {
        this.logger.warn(`Verify code: Invalid code - ${code}`);
        throw new BadRequestException('Invalid or expired reset code');
      }

      if (!user.resetCodeExpiry || user.resetCodeExpiry < new Date()) {
        this.logger.warn(`Verify code: Expired code - ${user.id}`);
        throw new BadRequestException('Invalid or expired reset code');
      }

      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error(`Failed to verify reset code: ${code}`, error);
      throw new InternalServerErrorException('Failed to verify reset code');
    }
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<MutationResponse> {
    try {
      this.logger.debug(
        `Password reset attempt with code: ${resetPasswordDto.code}`,
      );

      const user = await this.usersRepo.findOne({
        where: { resetCode: resetPasswordDto.code },
      });

      if (!user) {
        this.logger.warn(
          `Reset password: Invalid code - ${resetPasswordDto.code}`,
        );
        throw new BadRequestException('Invalid or expired reset code');
      }

      if (!user.resetCodeExpiry || user.resetCodeExpiry < new Date()) {
        this.logger.warn(`Reset password: Expired code - ${user.id}`);
        throw new BadRequestException('Invalid or expired reset code');
      }

      const hashedPassword: string = await bcrypt.hash(
        resetPasswordDto.newPassword,
        10,
      );

      user.password = hashedPassword;
      user.resetCode = null;
      user.resetCodeExpiry = null;
      await this.usersRepo.save(user);

      this.logger.log(`Password reset successfully for user: ${user.id}`);
      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Failed to reset password', String(error));
      throw new InternalServerErrorException('Failed to reset password');
    }
  }

  async logout(user: User, response: FastifyReply): Promise<MutationResponse> {
    try {
      this.logger.debug(`Logout request for user: ${user.id}`);

      await this.tokenService.removeToken(user.id);

      const cookieOptions = {
        domain: this.configService.get<string>('app.cookieDomain'),
        path: this.configService.get<string>('app.cookiePath'),
      };

      response.clearCookie('refresh_token', cookieOptions);
      response.clearCookie('access_token', cookieOptions);

      this.logger.log(`User logged out successfully: ${user.id}`);
      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error(`Logout failed for user: ${user.id}`, String(error));
      throw new InternalServerErrorException('Failed to logout');
    }
  }

  async refreshTokens(
    refreshToken: string,
    response: FastifyReply,
  ): Promise<MutationResponse> {
    try {
      const payload = this.tokenService.validateRefreshToken(refreshToken);

      if (!payload) {
        this.logger.warn('Token refresh: Invalid refresh token');
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.usersRepo.findOne({ where: { id: payload.sub } });

      if (!user) {
        this.logger.warn(`Token refresh: User not found - ${payload.sub}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      if (user.isBanned) {
        this.logger.warn(`Token refresh: Banned user attempted - ${user.id}`);
        throw new ForbiddenException(
          'Account is banned. Please contact support.',
        );
      }

      const tokens = await this.tokenService.generateTokens({
        sub: user.id,
      });

      this.configureCookies(response, tokens);

      this.logger.log(`Tokens refreshed successfully for user: ${user.id}`);
      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof ForbiddenException
      ) {
        throw error;
      }

      this.logger.error('Failed to refresh tokens', String(error));
      throw new InternalServerErrorException('Failed to refresh tokens');
    }
  }
}
