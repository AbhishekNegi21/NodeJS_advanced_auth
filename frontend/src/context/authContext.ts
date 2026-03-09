import { createContext } from "react";
import type { User, LoginResponse } from "../api/authApi";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  loginUser: (email: string, password: string) => Promise<LoginResponse>;
  logoutUser: () => Promise<void>;

  setUser: (user: User | null) => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
