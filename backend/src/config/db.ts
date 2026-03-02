import mongoose from "mongoose";

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("MongoDB connection successful");
  } catch (err) {
    console.log("MongoDB connection failed", err);
    process.exit(1);
  }
}
