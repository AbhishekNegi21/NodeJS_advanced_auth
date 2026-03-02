import { useState, useEffect } from "react";
import type { ReactNode } from "react";
import type { User } from "../api/authApi";
import { login, register, logout, getMe } from "../api/authApi";
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
      } catch (err) {
        console.log(err);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  const loginUser = async (email: string, password: string) => {
    const userData = await login(email, password);
    setUser(userData);
  };

  const registerUser = async (
    name: string,
    email: string,
    password: string,
  ) => {
    const userData = await register(name, email, password);
    setUser(userData);
  };

  const logoutUser = async () => {
    await logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        loginUser,
        registerUser,
        logoutUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
