import { Schema, model } from "mongoose";

const refreshTokenSchema = new Schema({
  userId: {
    // this is used to reference the user in the userModel
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  jti: {
    type: String,
    required: true,
    unique: true,
  },
  tokenHash: String,
  expiresAt: {
    type: Date,
    required: true,
    index: {
      // used to automatically clean up expired refresh tokens
      expires: 0,
    },
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
});

export const RefreshTokens = model("RefreshTokens", refreshTokenSchema);
