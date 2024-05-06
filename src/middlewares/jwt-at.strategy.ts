import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtPayload } from 'src/auth/types';
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class JwtAtStrategy extends PassportStrategy(Strategy, 'access-jwt') {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'at-secret',
    });
  }

  async validate(payload: JwtPayload) {
    const { sub } = payload;
    const user = await this.authService.findUserById(sub);
    if (!user) {
      throw new UnauthorizedException('Provide a valid access token');
    }
    return payload;
  }
}
