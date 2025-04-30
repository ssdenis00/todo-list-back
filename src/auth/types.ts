import type { User } from 'src/users';

export interface JwtPayload {
  sub: string; // ID пользователя
  email: string;
  iat?: number; // issued at
  exp?: number; // expiration time
}

export type SanitizedUser = Omit<User, 'password'>;
export type RefreshTokenPayload = JwtPayload & { refreshToken: string };

export type AuthUser = {
  userId: string;
  email: string;
  refreshToken?: string;
};
