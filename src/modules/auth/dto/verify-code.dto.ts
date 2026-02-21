import { Field, InputType } from '@nestjs/graphql';
import { IsNumber } from 'class-validator';

@InputType()
export class VerifyCodeDto {
  @Field()
  @IsNumber()
  code: number;
}
