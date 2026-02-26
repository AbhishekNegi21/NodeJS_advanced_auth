import { Router } from "express";
import {
  forgotPasswordHandler,
  googleAuthCallbackHandler,
  googleAuthStartHandler,
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  resetPasswordHandler,
  twoFactorAuthHandler,
  twoFactorVerifyHandler,
  verifyEmailHandler,
} from "../controllers/auth/authController";
import authenticate from "../middleware/authenticate";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshTokenHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler);
router.get("/google", googleAuthStartHandler);
router.get("/google/callback", googleAuthCallbackHandler);
router.post("/2fa/setup", authenticate, twoFactorAuthHandler);
router.post("/2fa/verify", authenticate, twoFactorVerifyHandler);

export default router;
