import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRouter from "./routes/authRoutes";
import userRouter from "./routes/userRoutes";
import adminRouter from "./routes/adminRoutes";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:5173", // frontend URL
    credentials: true, // allow sending cookies
  }),
);

app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/admin", adminRouter);

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

export default app;
