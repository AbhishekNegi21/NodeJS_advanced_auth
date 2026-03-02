import { Response, NextFunction } from "express";
import { AuthRequest } from "../types/AuthRequest";

function requireRole(role: "user" | "admin") {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    // get the authenticated user from the request handler
    const authUser = req.user;

    // check if the user is logged in
    if (!authUser) {
      return res.status(401).json({
        message: "Unauthorized user",
      });
    }

    // check if the roles match or not
    if (authUser.role !== role) {
      return res.status(403).json({
        message: "Unauthorized access",
      });
    }
    next();
  };
}
export default requireRole;
