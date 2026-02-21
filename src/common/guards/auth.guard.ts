import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { TokenService } from 'src/modules/auth/token.service';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { RequestWithAuth } from '../interfaces';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private tokenService: TokenService,
    private reflector: Reflector,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const gqlContext = GqlExecutionContext.create(context);
    const { req } = gqlContext.getContext<{ req: RequestWithAuth }>();

    const access_token = req.cookies?.access_token;

    if (!access_token) {
      if (isPublic) {
        return true;
      }
      this.logger.warn(
        `Unauthorized access attempt: Invalid authorization format`,
      );
      throw new UnauthorizedException('Session has expired.');
    }

    const payload = this.tokenService.validateAccessToken(access_token);

    if (!payload) {
      if (isPublic) {
        return true;
      }
      this.logger.warn(`Unauthorized access attempt: Invalid or expired token`);
      throw new UnauthorizedException('Session has expired.');
    }

    req.user = {
      id: payload.sub,
    };

    return true;
  }
}
