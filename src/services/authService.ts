import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User'; 
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import { Types } from 'mongoose';

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Function to hash the password
export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

// Function to compare passwords
export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

// Function to create JWT token
export const createJwtToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: '1h' });
};

// Function to create JWT refresh token
export const createRefreshToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET!, { expiresIn: '7d' });
};

// Function to verify Google OAuth token
export const verifyGoogleToken = async (token: string): Promise<any> => {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,  // Specify the client ID of your app
  });
  return ticket.getPayload();
};

// Function to create a new user in the database
export const registerUser = async (email: string, password?: string): Promise<IUser> => {
  const hashedPassword = password ? await hashPassword(password) : undefined;
  const user = new User({ email, password: hashedPassword });
  return user.save();
};

// Function to find a user by email
export const findUserByEmail = async (email: string): Promise<IUser | null> => {
  return User.findOne({ email });
};

// Function to handle user login
export const loginUser = async (email: string, password?: string, googleToken?: string): Promise<any> => {
  let user = await findUserByEmail(email);
  
  if (googleToken) {
    const googlePayload = await verifyGoogleToken(googleToken);
    if (!user) {
      user = await registerUser(email);  // Register new user if not found
    }
  } else {
    if (!user) {
      throw new Error('User not found');
    }

    const isMatch = await comparePassword(password!, user.password!);
    if (!isMatch) {
      throw new Error('Invalid credentials');
    }
  }

  // Explicitly cast _id to ObjectId to avoid type error
  const userId = user._id as Types.ObjectId;

  // Create tokens
  const accessToken = createJwtToken(userId.toString());
  const refreshToken = createRefreshToken(userId.toString());

  return { accessToken, refreshToken, user };
};

// Function to verify refresh token
export const verifyRefreshToken = (token: string): any => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

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
};

export default authService;