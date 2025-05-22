import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import { Types } from 'mongoose';
import axios from 'axios';

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// -------------------------
// Password Utilities
// -------------------------

export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

// -------------------------
// JWT Token Utilities
// -------------------------

export const createJwtToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: '1h' });
};

export const createRefreshToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET!, { expiresIn: '7d' });
};

export const verifyRefreshToken = (token: string): any => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

// -------------------------
// Google OAuth Verification
// -------------------------

export const verifyGoogleToken = async (token: string): Promise<any> => {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  return ticket.getPayload();
};

// -------------------------
// User Management
// -------------------------

export const registerUser = async (email: string, password?: string): Promise<IUser> => {
  const hashedPassword = password ? await hashPassword(password) : undefined;
  const user = new User({ email, password: hashedPassword });
  return user.save();
};

export const findUserByEmail = async (email: string): Promise<IUser | null> => {
  return User.findOne({ email });
};

export const loginUser = async (
  email: string,
  password?: string,
  googleToken?: string
): Promise<{ accessToken: string; refreshToken: string; user: IUser }> => {
  let user = await findUserByEmail(email);

  if (googleToken) {
    const googlePayload = await verifyGoogleToken(googleToken);
    if (!user) {
      user = await registerUser(email); // Auto-register if not found
    }
  } else {
    if (!user) throw new Error('User not found');
    const isMatch = await comparePassword(password!, user.password!);
    if (!isMatch) throw new Error('Invalid credentials');
  }

  const userId = user._id as Types.ObjectId;
  const accessToken = createJwtToken(userId.toString());
  const refreshToken = createRefreshToken(userId.toString());

  return { accessToken, refreshToken, user };
};

// -------------------------
// Unified Password Reset via API
// -------------------------

interface ResetPasswordData {
  newPassword: string;
  token?: string;
  emailOrPhone?: string;
  verificationCode?: string;
}

export const resetPassword = async (
  data: ResetPasswordData
): Promise<{ message: string }> => {
  try {
    const response = await axios.post('/api/reset-password', data);
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Password reset failed');
    }
    throw new Error('Network or server error');
  }
};

// -------------------------
// Export as a Unified Service
// -------------------------

const authService = {
  hashPassword,
  comparePassword,
  createJwtToken,
  createRefreshToken,
  verifyGoogleToken,
  registerUser,
  findUserByEmail,
  loginUser,
  verifyRefreshToken,
  resetPassword,
};

export default authService;
