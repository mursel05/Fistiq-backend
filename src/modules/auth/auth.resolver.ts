import type { FastifyReply } from 'fastify';
import { Resolver, Mutation, Args, Query, Context } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import { MutationResponse } from 'src/common/dto/mutation-response.dto';
import { UseGuards } from '@nestjs/common';
import type { RequestWithAuth } from 'src/common/interfaces';
import { VerifyCodeDto } from './dto/verify-code.dto';
import { AuthGuard } from 'src/common/guards/auth.guard';
import { User } from '../users/entities/user.entity';

@Resolver(() => User)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Query(() => User)
  me(@CurrentUser() user: User) {
    return user;
  }

  @Mutation(() => MutationResponse)
  register(
    @Args('input') body: RegisterDto,
    @Context() context: { res: FastifyReply },
  ) {
    return this.authService.register(body, context.res);
  }

  @Mutation(() => MutationResponse)
  login(
    @Args('input') body: LoginDto,
    @Context() context: { res: FastifyReply },
  ) {
    return this.authService.login(body, context.res);
  }

  @Mutation(() => MutationResponse)
  forgotPassword(@Args('input') body: ForgotPasswordDto) {
    return this.authService.forgotPassword(body);
  }

  @Mutation(() => MutationResponse)
  verifyCode(@Args('input') body: VerifyCodeDto) {
    return this.authService.verifyCode(body.code);
  }

  @Mutation(() => MutationResponse)
  resetPassword(@Args('input') body: ResetPasswordDto) {
    return this.authService.resetPassword(body);
  }

  @Mutation(() => MutationResponse)
  @UseGuards(AuthGuard)
  logout(@CurrentUser() user: User, @Context() context: { res: FastifyReply }) {
    return this.authService.logout(user, context.res);
  }

  @Mutation(() => MutationResponse)
  refreshToken(
    @Context() context: { res: FastifyReply; req: RequestWithAuth },
  ) {
    const { refresh_token } = context.req.cookies;
    return this.authService.refreshTokens(refresh_token, context.res);
  }
}
