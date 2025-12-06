import express from "express";
import cors from 'cors';
import {notFoundHandler,globalErrorHandler} from './middleware/middleware.error.js'
export const app = express();

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
//cors configuration
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POSST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type"],
  })
);
//import the routes
import { healthCheck } from "./controllers/healthcheck.controller.js";

//
app.use("/api/v1/healthcheck",healthCheck)


app.get("/", (req, res) => {
  res.send("Welcome to basecamp!!");
});




//Global Error handler and 404 handler


// 404 handler
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(globalErrorHandler);




