import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { User } from 'src/users';
import { AuthService } from './auth.service';
import { RefreshTokenGuard } from './guards';
import type { AuthUser } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() userData: { email: string; password: string }) {
    return this.authService.register(userData);
  }

  @Post('login')
  @UseGuards(AuthGuard('local'))
  async login(@Request() req: { user: User }) {
    return this.authService.login(req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req: { user: User }) {
    return req.user;
  }

  @Post('refresh')
  @UseGuards(RefreshTokenGuard)
  async refreshTokens(@Request() req: { user: AuthUser }) {
    if (!req.user.refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    return this.authService.refreshTokens(
      req.user.userId,
      req.user.refreshToken,
    );
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  async logout(@Request() req: { user: AuthUser }) {
    return this.authService.logout(req.user.userId);
  }
}
