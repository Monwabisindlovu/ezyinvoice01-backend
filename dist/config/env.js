"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.env = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, "../../.env") });
exports.env = {
    MONGO_URI: process.env.MONGO_URI || "mongodb://localhost:27017/ezyinvoice",
    JWT_SECRET: process.env.JWT_SECRET || "your_jwt_secret",
    REACT_APP_API_URL: process.env.REACT_APP_API_URL || "http://localhost:5000/api/auth",
    SMTP_USER: process.env.SMTP_USER || "your-email@example.com",
    SMTP_PASS: process.env.SMTP_PASS || "your-email-password",
    PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : 5000,
};
