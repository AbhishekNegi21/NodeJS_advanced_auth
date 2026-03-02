import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

export function createAccessToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const payload = { sub: userId, role, tokenVersion };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "30m",
  });
}

export function verifyAccessToken(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: "user" | "admin";
    tokenVersion: number;
  };
}

export function createRefreshToken(userId: string, tokenVersion: number) {
  const jti = randomUUID();
  const payload = { sub: userId, jti, tokenVersion };

  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: "7d",
  });

  return { refreshToken, jti };
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    jti: string;
    tokenVersion: number;
  };
}
