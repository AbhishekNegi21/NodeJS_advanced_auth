import { Request, Response } from "express";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from "./authSchema";
import { User } from "../../models/userModel";
import { checkPassword, hashPassword, hashRefreshToken } from "../../lib/hash";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import { RefreshTokens } from "../../models/tokenModel";
import { OAuth2Client } from "google-auth-library";
import { AuthRequest } from "../../types/AuthRequest";
import { generateSecret, generateURI, verify } from "otplib";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !!clientSecret) {
    throw new Error("Google client credentials missing");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    // validate the credentials using "safeParse" from zod
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid credentials",
        errors: result.error.flatten(),
      });
    }

    // extracting credentials from result data
    const { name, email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    // check if email already exists in the database
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      // The 409 error means the same entity is being used already
      return res.status(409).json({
        message: "Email is already in use! Please try with a different email",
      });
    }

    // hash the password
    const passwordHash = await hashPassword(password);

    // save the user in the db
    const newUser = await User.create({
      name,
      email: normalizedEmail,
      passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    // creating a short lived jwt for email verification
    const verificationToken = jwt.sign(
      {
        sub: newUser.id,
      },
      process.env.JWT_EMAIL_VERIFY_SECRET!,
      {
        expiresIn: "15m",
      },
    );

    // setup a verify url
    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verificationToken}`;

    // send an email
    await sendEmail(
      newUser.email,
      "Verify your email",
      `<p>please verify your email by clicking on this link:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      `,
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser.id,
        name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (err) {
    console.log("Error occurred!", err);
    res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  // get the token from the request query paramater
  const token = req.query.token as string | undefined;

  // check if the token is present or not
  if (!token) {
    return res.status(400).json({
      message: "Verification token is missing",
    });
  }

  // verify the jwt and get the payload back
  try {
    // telling TS that payload has a sub field, and its a string
    // sub is subject i.e userID
    const payload = jwt.verify(token, process.env.JWT_EMAIL_VERIFY_SECRET!) as {
      sub: string;
    };

    // check if the user exists in the database
    // (here payload is the decoded token and sub is the userID)
    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    // check if the email is already verified
    if (user.isEmailVerified) {
      return res.json({
        message: "Email is already verified",
      });
    }

    // if not mark the "isEmailVerified" as true
    user.isEmailVerified = true;

    // save the user data in the db
    await user.save();

    return res.status(200).json({
      message: "Email is now verified. You can now login.",
    });
  } catch (err: any) {
    if (err?.name === "TokenExpiredError") {
      return res.status(400).json({
        message: "Verification link has expired",
      });
    }

    if (err?.name === "JsonWebTokenError") {
      return res.status(400).json({
        message: "Invalid verification token",
      });
    }

    console.log("Error occurred!", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    // validate the credentials using "safeParse" from zod
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid email or password",
        errors: result.error.flatten(),
      });
    }

    // extract the data from the result data
    const { email, password, twoFactorCode } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    // check is user exists in the database
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    // if user exists, check if the password is correct
    // the user contains the hashed password field
    const isCorrectPassword = await checkPassword(password, user.passwordHash);

    // if not , return invalid password
    if (!isCorrectPassword) {
      return res.status(400).json({
        message: "Invalid Password.",
      });
    }

    // if email is not verified, return a 403 error
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in.",
      });
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== "string") {
        return res.status(400).json({
          message: "Two factor code required",
        });
      }

      if (!user.twoFactorSecret) {
        return res.status(400).json({
          message: "Two factor not configured",
        });
      }

      // verify the two factor code
      const isValidCode = verify({
        secret: user.twoFactorSecret,
        token: twoFactorCode,
      });

      if (!isValidCode) {
        return res.status(400).json({
          message: "Invalid two factor code",
        });
      }
    }

    // if correct , create an access token
    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );

    // create a refresh token including jti
    const { refreshToken, jti } = createRefreshToken(
      user.id,
      user.tokenVersion,
    );

    // hash the refresh token
    const refreshTokenHash = await hashRefreshToken(refreshToken);

    // save the refresh token in the db with id, jti and expiresAt
    await RefreshTokens.create({
      userId: user.id,
      jti,
      tokenHash: refreshTokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // check if the environment is production
    const isProduction = process.env.NODE_ENV === "production";

    // create a cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Logged in successfully.",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (err) {
    console.log("Error occurred!", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    // extracting the refresh token from the cookie
    const token = req.cookies?.refreshToken as string | undefined;
    if (!token) {
      return res.status(401).json({
        message: "Refresh token missing",
      });
    }

    // verify the refresh token
    const payloadData = verifyRefreshToken(token);

    // extract the user data from payloadData
    const { sub: userId, jti } = payloadData;

    // check whether user exists in db or not
    const user = await User.findById(userId);

    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    // check whether token versions match or not
    if (user.tokenVersion !== payloadData.tokenVersion) {
      return res.status(400).json({
        message: "Refresh token invalidated",
      });
    }

    // Look up the refresh token record in the db using the `jti` from the JWT
    const isJTI = await RefreshTokens.findOne({ jti });

    // If token doesnt exist in DB, it's been revoked or already used → reject the request
    if (!isJTI) {
      // possible refresh token reuse attack
      await RefreshTokens.deleteMany({ userId });

      user.tokenVersion += 1;
      await user.save();

      return res.status(401).json({
        message: "Session expired. PLease login again",
      });
    }

    // delete the old token
    await isJTI.deleteOne();

    // creating a new access token
    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );

    // creating a new refresh token
    const { refreshToken: newRefreshToken, jti: newJTI } = createRefreshToken(
      user.id,
      user.tokenVersion,
    );

    // hash the new refresh token
    const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);

    // save the new refresh token in the database
    await RefreshTokens.create({
      userId: user.id,
      jti: newJTI,
      tokenHash: newRefreshTokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // check if the environment is production
    const isProduction = process.env.NODE_ENV === "production";

    // create a cookie to store the refresh token
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Token refreshed successfully",
      newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (err) {
    console.log("Error occurred!", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  res.clearCookie("refreshToken", { path: "/" });

  return res.status(200).json({
    message: "Logged out.",
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  // validate the credentials using "safeParse" from zod
  const result = forgotPasswordSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({
      message:
        "If an account with this email exists, we will send you a reset link.",
    });
  }
  // extract the email from result data
  const { email } = result.data;

  // normalize the email
  const normalizedEmail = email.toLowerCase().trim();

  try {
    // find the user in the database
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          "If an account with this email exists, we will send you a reset link.",
      });
    }

    // create a raw token
    const rawToken = crypto.randomBytes(32).toString("hex");

    // create a hash of the token
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    // assign the hashed token to the reset password token
    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
    // the expiry is set as 15 minute after the token is issued

    // save the user
    await user.save();

    // set up a reset password Url
    const resetUrl = `${getAppUrl}/auth/reset-password?token=${rawToken}`;

    // send reset email
    await sendEmail(
      user.email,
      "Reset your password",
      `<p><a href="${resetUrl}">Reset your password</a></p>
      <p>${resetUrl}</p>
      `,
    );

    return res.status(200).json({
      message:
        "If an account with this email exists, we will send you a reset link.",
    });
  } catch (err) {
    console.log("Error occurred!", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  // validate the input credentials with zod
  const result = resetPasswordSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({
      message: "Invalid or expired reset request ",
    });
  }

  // extract the reset token and password from result data
  const { token, password } = result.data;

  try {
    // create the token hash
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // find the user in the database
    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
      // we are checking whether the expiry time has passed or not.
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset request",
      });
    }

    // hash the new password
    const newPasswordHash = await hashPassword(password);

    // set the hashed password as the user password
    user.passwordHash = newPasswordHash;

    // set the reset token and reset password expiry to undefined
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // increment the token version
    user.tokenVersion = user.tokenVersion + 1;

    // save the user in the db
    await user.save();

    return res.status(200).json({
      message: "Password reset successfully.",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error!",
    });
  }
}

export async function googleAuthStartHandler(req: Request, res: Response) {
  try {
    // create a google client
    const client = getGoogleClient();

    // create a state parameter
    const state = crypto.randomBytes(32).toString("hex");

    // store the state in a http cookie
    res.cookie("oauth_state", state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 5 * 60 * 1000,
    });

    // generate a scope url
    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
      state,
    });

    return res.redirect(url);
  } catch (err) {
    console.log("Google auth start error:", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  // validating oAuth state
  const stateFromQuery = req.query.state as string | undefined;
  const stateFromCookie = req.cookies.oauth_state;

  if (!stateFromQuery || stateFromQuery !== stateFromCookie) {
    return res.status(400).json({
      message: "Invalid OAuth state",
    });
  }

  // Clear cookie if validation is successfull
  res.clearCookie("oauth_state");

  // extract the code from the query parameter
  const code = req.query.code as string | undefined;

  if (!code) {
    return res.status(400).json({
      message: "Missing code",
    });
  }

  try {
    // call the google client
    const client = getGoogleClient();

    // extract the token from client
    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(400).json({
        message: "google id token not present",
      });
    }

    // verify id tokens and read the user data from it
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    // get the payload from the ticket
    const payload = ticket.getPayload();

    if (!payload) {
      return res.status(400).json({ message: "Invalid ID token payload" });
    }

    // extract the email and emailVerified from the payload
    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email) {
      return res.status(400).json({ message: "Email not present in token" });
    }

    if (!emailVerified) {
      return res.status(403).json({ message: "Google email not verified" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // find the user in the db
    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      // create a password and hash it
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      // create a new user in the db
      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    // create access and refresh token
    const accessToken = createAccessToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion,
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    // check if the environment is production
    const isProduction = process.env.NODE_ENV === "production";

    // create a cookie to store the refresh token
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // return a 200 response
    return res.status(200).json({
      message: "Google login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (err) {
    console.log("Google callback error!", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function twoFactorAuthHandler(req: AuthRequest, res: Response) {
  const authUser = req.user;

  if (!authUser) {
    return res.status(400).json({
      message: "Not authenticated",
    });
  }

  try {
    // find the user in the db
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // generate a secret using optlib generateSecret
    const secret = generateSecret();

    const issuer = "NodeAdvancedAuthApp";

    const otpAuthUrl = generateURI({
      issuer,
      label: user.email,
      secret,
    });

    // set the secret as the twoFactorSecret
    user.twoFactorSecret = secret;

    // save the user in the db
    await user.save();

    // return a 200 resposne
    return res.json({
      message: "2FA setup successfull",
      otpAuthUrl,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function twoFactorVerifyHandler(req: AuthRequest, res: Response) {
  const authUser = req.user;

  if (!authUser) {
    return res.status(400).json({
      message: "Not authenticated",
    });
  }

  const { code } = req.body as { code?: string };

  if (!code) {
    return res.status(400).json({
      message: "Two factor code required",
    });
  }

  try {
    // find the user in the db
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({
        message: "2FA setup not done.",
      });
    }

    const isValid = verify({
      secret: user.twoFactorSecret,
      token: code,
    });

    if (!isValid) {
      return res.status(400).json({
        message: "Invalid 2FA code",
      });
    }

    // mark the twoFactorEnabed as true
    user.twoFactorEnabled = true;

    // save the user
    await user.save();

    // return a 200 response
    return res.status(200).json({
      message: "2FA enabled successfully",
      twoFactorEnabled: true,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
