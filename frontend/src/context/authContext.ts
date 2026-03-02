import { createContext } from "react";
import type { User } from "../api/authApi";

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  loading: boolean;

  loginUser: (user: User, accessToken: string) => void;
  logoutUser: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
