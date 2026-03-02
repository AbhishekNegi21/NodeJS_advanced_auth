import { Request, Response, Router } from "express";
import authenticate from "../middleware/authenticate";
import requireRole from "../middleware/requireRole";
import { User } from "../models/userModel";

const router = Router();

router.get(
  "/users",
  authenticate,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    try {
      const users = await User.find(
        {}, // find all users

        {
          // projection object, return only those with value 1
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        },
      ).sort({ createdAt: -1 }); // descending order

      const result = users.map((user) => ({
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        createdAt: user.createdAt,
      }));

      return res.json({
        users: result,
      });
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        message: "Internal server error",
      });
    }
  },
);

export default router;
