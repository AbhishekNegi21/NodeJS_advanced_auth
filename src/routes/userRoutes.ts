import { Response, Router } from "express";
import authenticate from "../middleware/authenticate";
import { AuthRequest } from "../types/AuthRequest";

const router = Router();

router.get("/me", authenticate, (req: AuthRequest, res: Response) => {
  return res.json({
    user: req.user,
  });
});

export default router;
