import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.resolve(__dirname, "../../.env") });

export const env = {
  MONGO_URI: process.env.MONGO_URI || "mongodb://localhost:27017/ezyinvoice",
  JWT_SECRET: process.env.JWT_SECRET || "your_jwt_secret",
  REACT_APP_API_URL: process.env.REACT_APP_API_URL || "http://localhost:5000/api/auth",
  SMTP_USER: process.env.SMTP_USER || "your-email@example.com",
  SMTP_PASS: process.env.SMTP_PASS || "your-email-password",
  PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : 5000,
};