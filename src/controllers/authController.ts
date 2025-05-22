import { Request, Response, NextFunction } from 'express';
import { validateRegister, handleValidationErrors } from '../middleware/validationMiddleware';
import * as encryptUtils from '../utils/encrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import User from '../models/User';
import { OAuth2Client } from 'google-auth-library';
import sendResetEmail from '../utils/sendEmail';
import { sendPasswordResetEmail } from '../utils/sendEmail';
import { sendResetSMS } from '../utils/smsService';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Function to validate password with specified rules
const validatePassword = (pwd: string): boolean => {
  return (
    pwd.length >= 7 &&
    pwd.length <= 12 &&
    /[A-Za-z]/.test(pwd) &&
    /\d/.test(pwd) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(pwd)
  );
};

// JWT Authentication Middleware
const authenticateJWT = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1];
    const decoded: JwtPayload = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
    const user = await User.findById(decoded.id).exec();

    if (!user) {
      return res.status(401).json({ message: "Invalid token." });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('JWT Authentication Error:', error);
    res.status(401).json({ message: "Invalid or expired token." });
  }
};

const AuthController = {
  register: [
    ...validateRegister,
    handleValidationErrors,
    async (req: Request, res: Response) => {
      try {
        console.log('Incoming Request Body:', req.body);

        const { email, phone, password } = req.body;

        if (!email && !phone) {
          console.log('Validation Error: Email or phone is required');
          return res.status(400).json({ message: 'Email or phone is required' });
        }

        console.log('Checking for existing user...');
        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
        if (existingUser) {
          console.log('Validation Error: User already exists');
          return res.status(400).json({ message: 'User already exists' });
        }

        console.log('Hashing password...');
        const hashedPassword = await encryptUtils.hashPassword(password);
        console.log('Password hashed successfully');

        console.log('Creating new user...');
        const newUser = new User({
          email,
          phone,
          password: hashedPassword,
        });

        await newUser.save();
        console.log('New user created and saved successfully');

        res.status(201).json({ message: 'User registered successfully' });
      } catch (error) {
        if (error instanceof Error) {
          if (error.message.includes('E11000')) {
            console.log('Duplicate key error:', error.message);
            return res.status(400).json({ message: 'User with this email or phone already exists' });
          }

          console.error('Registration Server Error:', {
            message: error.message,
            stack: error.stack,
          });
          res.status(500).json({ message: 'Server error', error: error.message });
        } else {
          console.error('Unexpected error:', error);
          res.status(500).json({ message: 'Server error', error });
        }
      }
    }
  ],
  login: async (req: Request, res: Response) => {
    try {
      console.log('Login Request Body:', req.body);

      const { emailOrPhone, password } = req.body;

      if (!emailOrPhone) {
        return res.status(400).json({ message: 'Email or phone is required' });
      }

      let phone = emailOrPhone;
      if (phone && !phone.startsWith('+')) {
        phone = `+27${phone.substring(1)}`;
      }

      const user = await User.findOne({
        $or: [
          { email: emailOrPhone },
          { phone },
        ],
      });

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      console.log('User found:', user);
      const isPasswordValid = await encryptUtils.comparePassword(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const token = user.generateJwtToken();
      res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
      if (error instanceof Error) {
        console.error('Login Server Error:', {
          message: error.message,
          stack: error.stack,
        });
        res.status(500).json({ message: 'Server error', error: error.message });
      } else {
        console.error('Unexpected error:', error);
        res.status(500).json({ message: 'Server error', error });
      }
    }
  },
  googleAuth: async (req: Request, res: Response) => {
    try {
      const { token } = req.body;
      if (!token) {
        return res.status(400).json({ message: 'Token is required.' });
      }

      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      const googlePayload = ticket.getPayload();
      if (!googlePayload) {
        return res.status(400).json({ message: 'Invalid Google token' });
      }

      const { email, sub: googleId, name, picture } = googlePayload;
      let user = await User.findOne({ email }).exec();

      if (!user) {
        user = new User({
          email,
          googleId,
          name,
          avatar: picture,
          password: 'google-oauth', // Dummy password; consider handling this appropriately
        });
        await user.save();
        console.log('🔹 New Google user created:', user);
      } else {
        if (!(user instanceof User)) {
          user = await User.findById(user._id).exec();
        }
        console.log('🔹 Existing user found:', user);
      }

      // Ensure user is not null before generating JWT
      if (!user) {
        return res.status(404).json({ message: 'User not found after checking' });
      }
      const jwtToken = user.generateJwtToken();
      console.log('🔹 JWT Token generated:', jwtToken);

      res.status(200).json({ token: jwtToken, user });
    } catch (error) {
      console.error('Google Auth Error:', error);
      res.status(500).json({
        message: 'Server error',
        error: error instanceof Error ? error.message : error,
      });
    }
  },

  forgotPassword: async (req: Request, res: Response) => {
    try {
      const { emailOrPhone } = req.body;
      if (!emailOrPhone) {
        return res.status(400).json({ message: 'Email or phone is required' });
      }

      const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
      if (!user) {
        return res.status(400).json({ message: 'User not found' });
      }

      const resetToken = encryptUtils.generateRandomToken();
      if (user.email === emailOrPhone) {
        await sendPasswordResetEmail(user.email, resetToken);
        res.json({ message: 'Password reset email sent' });
      } else if (user.phone === emailOrPhone) {
        if (!user.phone) {
          return res.status(400).json({ message: 'User phone number is missing' });
        }
        await sendResetSMS(user.phone, resetToken);
        res.json({ message: 'Password reset SMS sent' });
      }
    } catch (error) {
      if (error instanceof Error) {
        console.error('Forgot Password Server Error:', {
          message: error.message,
          stack: error.stack,
        });
        res.status(500).json({ message: 'Server error', error: error.message });
      } else {
        console.error('Unexpected error:', error);
        res.status(500).json({ message: 'Server error', error });
      }
    }
  },

  resetPassword: async (req: Request, res: Response): Promise<void> => {
    const { emailOrPhone, verificationCode, token, newPassword } = req.body;

    if (!validatePassword(newPassword)) {
      res.status(400).json({
        message:
          'Password must be 7-12 characters long, contain at least one letter, one number, and one special character',
      });
      return;
    }

    if (!process.env.JWT_SECRET) {
      res.status(500).json({ message: 'Server error: Missing JWT secret' });
      return;
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET) as JwtPayload;
      const user = await User.findById(decoded.id);

      if (!user) {
        res.status(400).json({ message: 'Invalid token or user not found' });
        return;
      }

      user.password = await encryptUtils.hashPassword(newPassword);
      await user.save();

      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      if (error instanceof Error) {
        console.error('Reset Password Server Error:', {
          message: error.message,
          stack: error.stack,
        });
        res.status(500).json({ message: 'Server error', error: error.message });
      } else {
        console.error('Unexpected error:', error);
        res.status(500).json({ message: 'Server error', error });
      }
    }
  }
};

export default AuthController;
