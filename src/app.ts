import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./routes/authRoutes";
import userRouter from "./routes/userRoutes";
import adminRouter from "./routes/adminRoutes";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/admin", adminRouter);

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

export default app;
