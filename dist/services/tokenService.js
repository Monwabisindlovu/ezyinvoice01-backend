"use strict";
// src/services/tokenService.ts
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.refreshAccessToken = exports.isTokenBlacklisted = exports.blacklistToken = exports.verifyRefreshToken = exports.verifyAccessToken = exports.createRefreshToken = exports.createAccessToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
// In-memory blacklist for invalidated tokens (you can use a database or a cache like Redis for production)
let tokenBlacklist = new Set();
// Function to create a JWT access token
const createAccessToken = (userId) => {
    return jsonwebtoken_1.default.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};
exports.createAccessToken = createAccessToken;
// Function to create a JWT refresh token
const createRefreshToken = (userId) => {
    return jsonwebtoken_1.default.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
};
exports.createRefreshToken = createRefreshToken;
// Function to verify the JWT access token
const verifyAccessToken = (token) => {
    try {
        // Check if the token is blacklisted
        if (tokenBlacklist.has(token)) {
            throw new Error('Token is blacklisted');
        }
        return jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
    }
    catch (error) {
        throw new Error('Invalid or expired access token');
    }
};
exports.verifyAccessToken = verifyAccessToken;
// Function to verify the JWT refresh token
const verifyRefreshToken = (token) => {
    try {
        return jsonwebtoken_1.default.verify(token, process.env.JWT_REFRESH_SECRET);
    }
    catch (error) {
        throw new Error('Invalid or expired refresh token');
    }
};
exports.verifyRefreshToken = verifyRefreshToken;
// Function to blacklist a refresh token (e.g., when a user logs out)
const blacklistToken = (token) => {
    tokenBlacklist.add(token);
};
exports.blacklistToken = blacklistToken;
// Function to check if a refresh token is blacklisted
const isTokenBlacklisted = (token) => {
    return tokenBlacklist.has(token);
};
exports.isTokenBlacklisted = isTokenBlacklisted;
// Function to refresh the access token using a valid refresh token
const refreshAccessToken = (refreshToken) => {
    try {
        // Verify the refresh token first
        const decoded = (0, exports.verifyRefreshToken)(refreshToken);
        // If the refresh token is valid, create a new access token
        const newAccessToken = (0, exports.createAccessToken)(decoded.userId);
        return newAccessToken;
    }
    catch (error) {
        throw new Error('Failed to refresh access token');
    }
};
exports.refreshAccessToken = refreshAccessToken;
