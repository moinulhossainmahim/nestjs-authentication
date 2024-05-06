import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto, GoogleSignInCredentialsDto } from './dto';
import { JwtPayload, Tokens } from './types';
import { AtJwtAuthGuard, RtJwtAuthGuard } from 'src/guards';
import { GetUser } from 'src/decorators/get-user.decorator';
import { JwtPayloadWithRt } from './types';
import { LoginResponse } from './types/loginResponse';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(authDto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(
    @Body() authDto: Omit<AuthDto, 'fullName'>,
  ): Promise<LoginResponse> {
    return this.authService.signinLocal(authDto);
  }

  @Post('/google/signin')
  GoogleSignIn(
    @Body() googleSignInCredentialsDto: GoogleSignInCredentialsDto,
  ): Promise<LoginResponse> {
    return this.authService.googleSignIn(googleSignInCredentialsDto);
  }

  @UseGuards(AtJwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser() user: JwtPayload) {
    return this.authService.logout(user.sub);
  }

  @UseGuards(RtJwtAuthGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetUser() user: JwtPayloadWithRt) {
    return this.authService.refreshTokens(user.sub, user.refreshToken);
  }
}
