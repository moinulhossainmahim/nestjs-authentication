import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload, JwtPayloadWithRt } from 'src/auth/types';

export const GetUser = createParamDecorator(
  (_data, ctx: ExecutionContext): JwtPayload | JwtPayloadWithRt => {
    const req = ctx.switchToHttp().getRequest();
    return req.user;
  },
);
