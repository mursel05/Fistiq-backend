import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PayloadTokenDto } from './dto/payload-token.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Token } from './entities/token.entity';
import { LessThan, Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  constructor(
    @InjectRepository(Token)
    private tokensRepo: Repository<Token>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async generateTokens(payload: PayloadTokenDto): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const accessToken = this.jwtService.sign(payload, {
        secret: this.configService.get('auth.jwtAccessSecret'),
        expiresIn: this.configService.get('auth.jwtAccessExpiresIn'),
      });
      const refreshToken = this.jwtService.sign(payload, {
        secret: this.configService.get('auth.jwtRefreshSecret'),
        expiresIn: this.configService.get('auth.jwtRefreshExpiresIn'),
      });
      const token = await this.tokensRepo.findOne({
        where: { userId: payload.sub },
      });
      if (token) {
        token.token = refreshToken;
        token.expiresAt = new Date(
          Date.now() +
            Number(this.configService.get('auth.refreshTokenExpiryMs')),
        );
        await this.tokensRepo.save(token);
      } else {
        await this.tokensRepo.save({
          userId: payload.sub,
          token: refreshToken,
          expiresAt: new Date(
            Date.now() +
              Number(this.configService.get('auth.refreshTokenExpiryMs')),
          ),
        });
      }
      return { accessToken, refreshToken };
    } catch (error) {
      this.logger.error(`Failed to generate tokens: ${error}`);
      throw new InternalServerErrorException('Could not generate tokens');
    }
  }

  validateAccessToken(token: string): PayloadTokenDto | null {
    try {
      const userData = this.jwtService.verify<PayloadTokenDto>(token, {
        secret: this.configService.get('auth.jwtAccessSecret'),
      });
      return userData;
    } catch {
      return null;
    }
  }

  validateRefreshToken(token: string): PayloadTokenDto | null {
    try {
      const userData = this.jwtService.verify<PayloadTokenDto>(token, {
        secret: this.configService.get('auth.jwtRefreshSecret'),
      });
      return userData;
    } catch {
      return null;
    }
  }

  async removeToken(userId: number): Promise<void> {
    try {
      await this.tokensRepo.delete({ userId });
    } catch (error) {
      this.logger.error(`Failed to remove token for user ${userId}: ${error}`);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleExpiredTokens() {
    try {
      await this.tokensRepo.delete({
        expiresAt: LessThan(new Date()),
      });
    } catch (error) {
      this.logger.error('Failed to cleanup expired tokens', String(error));
    }
  }
}
