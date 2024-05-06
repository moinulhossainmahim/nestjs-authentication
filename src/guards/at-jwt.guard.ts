import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JsonWebTokenError } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AtJwtAuthGuard extends AuthGuard('access-jwt') {
  handleRequest(err: any, user: any, info: any, context: any, status: any) {
    console.log(info);
    if (info?.message === 'jwt expired') {
      throw new ForbiddenException('Provide a valid token');
    }

    if (info instanceof JsonWebTokenError) {
      throw new UnauthorizedException('Provide a valid token');
    }

    return super.handleRequest(err, user, info, context, status);
  }
}
