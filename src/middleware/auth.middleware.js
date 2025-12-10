import jwt from "jsonwebtoken";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asynHandler.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  /*
      MENTAL FLOW:
      1. Extract token from cookies OR Authorization header.
      2. If no token → Unauthorized (401).
      3. Verify token using JWT secret.
      4. Extract userId from decoded token.
      5. Fetch user from DB (remove sensitive fields).
      6. If no user → Unauthorized.
      7. Attach user to req.user.
      8. Move to next middleware.
      9. If any JWT error → throw 401.
  */
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace(/Bearer\s+/i, ""); //Bearer\s+/i this syntax replace bearer or Bearer with nothing

  if (!token) {
    throw new ApiError(400, "Access token missing!!!");
  }

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
    );
    if (!user) {
      throw new ApiError(400, "user not found !!");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(400, "Invalid or expired access token!!!");
  }
});
