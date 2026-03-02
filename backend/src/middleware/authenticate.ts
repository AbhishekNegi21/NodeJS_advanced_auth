import { Response, NextFunction } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/userModel";
import { AuthRequest } from "../types/AuthRequest";

async function authenticate(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) {
  // get the auth header from request header
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authorization token missing.",
    });
  }

  // split and extract the bearer token
  // accessing the first element after the space which is the token
  const token = authHeader.split(" ")[1];

  try {
    // verify and extract the payload
    const payload = verifyAccessToken(token);

    // find the user in the db using payload.sub i.e userId
    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        message: "User not found. Unauthorized",
      });
    }

    // check if token versions match or not
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    // attach authenticated user data to req.user
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    // call the next() handler
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).json({
      message: "Unauthorized",
    });
  }
}

export default authenticate;
