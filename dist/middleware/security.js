"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.enforceHttps = exports.corsMiddleware = exports.securityMiddleware = void 0;
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
// Enable Helmet for securing HTTP headers
exports.securityMiddleware = (0, helmet_1.default)();
// CORS configuration
const corsOptions = {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
exports.corsMiddleware = (0, cors_1.default)(corsOptions);
// Enforce HTTPS
const enforceHttps = (req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
};
exports.enforceHttps = enforceHttps;
