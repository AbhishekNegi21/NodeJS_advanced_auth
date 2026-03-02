import { fetchClient, setAccessToken } from "./fetchClient";

export interface User {
  _id: string;
  name: string;
  email: string;
  role: string;
}

export interface AuthResponse {
  user: User;
  accessToken: string;
}

export interface TwoFactorResponse {
  twoFactorRequired: true;
  userId: string;
}

export type LoginResponse = AuthResponse | TwoFactorResponse;

export const login = async (
  email: string,
  password: string,
): Promise<LoginResponse> => {
  return fetchClient<AuthResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
};

export const register = async (
  name: string,
  email: string,
  password: string,
): Promise<User> => {
  const data: AuthResponse = await fetchClient<AuthResponse>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ name, email, password }),
  });
  setAccessToken(data.accessToken);
  return data.user;
};

export const getMe = async (): Promise<User> => {
  const data: AuthResponse = await fetchClient<AuthResponse>("/auth/me");
  setAccessToken(data.accessToken);
  return data.user;
};

export const logout = async () => {
  await fetchClient("/auth/logout", { method: "POST" });
  setAccessToken(null);
};
