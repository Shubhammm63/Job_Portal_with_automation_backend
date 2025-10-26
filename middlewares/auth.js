import { catchAsyncError } from "./catchAsyncError.js";
import ErrorHandler from "./error.js";
import jwt from "jsonwebtoken";
import { User } from "../models/userSchema.js";

// Middleware: Checks if user is logged in
export const isAuthenticated = catchAsyncError(async (req, res, next) => {
  // FIX: directly access the cookie safely
  const token = req.cookies?.token;

  if (!token) {
    return next(new ErrorHandler("User is not authenticated.", 401));
  }

  // Verify token
  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  // Fetch user
  req.user = await User.findById(decoded.id);

  if (!req.user) {
    return next(new ErrorHandler("User not found.", 404));
  }

  next();
});

// Middleware: Checks if user has a specific role
export const isAuthorized = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorHandler(`${req.user.role} is not allowed to access this resource.`, 403)
      );
    }
    next();
  };
};
