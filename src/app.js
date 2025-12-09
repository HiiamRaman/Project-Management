import express from "express";
import { asyncHandler } from "./utils/asynHandler.js";
import cors from "cors";
import {
  notFoundHandler,
  globalErrorHandler,
} from "./middleware/middleware.error.js";
import cookieParser from "cookie-parser";
export const app = express();

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser())
//cors configuration
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type"],
  })
);
//import the routes  (user export default for routing)
import healthCheckrouter from "./routes/healthcheck.routes.js";
import registerUserrouter from "./routes/auth.routes.js";
//
app.use("/api/v1/healthcheck", healthCheckrouter);
app.use("/api/v1/auth", registerUserrouter);

app.get("/", (req, res) => {
  res.send("Welcome to basecamp!!");
});

//Global Error handler and 404 handler

// 404 handler
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(globalErrorHandler);
