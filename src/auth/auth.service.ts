import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import type { CreateUserDto } from 'src/users/create-user.dto';
import type { User } from '../users/users.entity';
import { UsersService } from '../users/users.service';
import type { TokensDto } from './tokens.dto';
import type { SanitizedUser } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async validateUser(
    email: string,
    pass: string,
  ): Promise<SanitizedUser | null> {
    const user = await this.usersService.findOne(email);
    if (!user) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(pass, user.password);

    if (!isPasswordValid) {
      return null;
    }

    const { password: _, ...rest } = user;
    return rest;
  }

  async register(userData: CreateUserDto): Promise<User> {
    // Проверяем существование пользователя
    const existingUser = await this.usersService.findOne(userData.email);
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    // Хешируем пароль и создаем пользователя
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    return this.usersService.create({
      ...userData,
      password: hashedPassword,
    });
  }

  async login(user: User): Promise<TokensDto> {
    const tokens = this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  async refreshTokens(
    userId: string,
    refreshToken: string,
  ): Promise<TokensDto> {
    const user = await this.usersService.findById(userId);

    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const isTokenValid = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!isTokenValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const tokens = this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  private generateTokens(user: User): TokensDto {
    const payload = {
      sub: user.id,
      email: user.email,
    };

    return {
      accessToken: this.jwtService.sign(payload, {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get('JWT_ACCESS_EXPIRES_IN'),
      }),
      refreshToken: this.jwtService.sign(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN'),
      }),
    };
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.usersService.update(userId, { refreshToken: hashedToken });
  }

  async logout(userId: string) {
    await this.usersService.update(userId, { refreshToken: null });
  }
}
