// src/services/tokenService.ts

import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// In-memory blacklist for invalidated tokens (you can use a database or a cache like Redis for production)
let tokenBlacklist: Set<string> = new Set();

// Function to create a JWT access token
export const createAccessToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: '1h' });
};

// Function to create a JWT refresh token
export const createRefreshToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET!, { expiresIn: '7d' });
};

// Function to verify the JWT access token
export const verifyAccessToken = (token: string): any => {
  try {
    // Check if the token is blacklisted
    if (tokenBlacklist.has(token)) {
      throw new Error('Token is blacklisted');
    }
    return jwt.verify(token, process.env.JWT_SECRET!);
  } catch (error) {
    throw new Error('Invalid or expired access token');
  }
};

// Function to verify the JWT refresh token
export const verifyRefreshToken = (token: string): any => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

// Function to blacklist a refresh token (e.g., when a user logs out)
export const blacklistToken = (token: string): void => {
  tokenBlacklist.add(token);
};

// Function to check if a refresh token is blacklisted
export const isTokenBlacklisted = (token: string): boolean => {
  return tokenBlacklist.has(token);
};

// Function to refresh the access token using a valid refresh token
export const refreshAccessToken = (refreshToken: string): string => {
  try {
    // Verify the refresh token first
    const decoded = verifyRefreshToken(refreshToken);

    // If the refresh token is valid, create a new access token
    const newAccessToken = createAccessToken(decoded.userId);
    return newAccessToken;
  } catch (error) {
    throw new Error('Failed to refresh access token');
  }
};