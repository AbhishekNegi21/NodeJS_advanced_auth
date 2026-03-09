import { useState, useEffect } from "react";
import type { ReactNode } from "react";
import type { User, LoginResponse } from "../api/authApi";
import { login, logout, getMe } from "../api/authApi";
import { setAccessToken } from "../api/fetchClient";
import { AuthContext } from "./authContext";

interface Props {
  children: ReactNode;
}

export const AuthProvider = ({ children }: Props) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const userData = await getMe();
        setUser(userData);
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  const loginUser = async (
    email: string,
    password: string,
  ): Promise<LoginResponse> => {
    const data = await login(email, password);

    if ("accessToken" in data) {
      setUser(data.user);
      setAccessToken(data.accessToken);
    }

    return data;
  };

  const logoutUser = async () => {
    await logout();
    setUser(null);
    setAccessToken(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        loginUser,
        logoutUser,
        setUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
