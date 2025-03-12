import express, { Request, Response, Router, NextFunction } from "express";
import { OAuth2Client } from "google-auth-library";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import passport from "passport";
import User from "../models/User";
import authService from "../services/authService";
import { UserSignup, UserTokenPayload } from "../types/userTypes";
import sendPasswordResetEmail from "../utils/sendEmail";
import encryptUtils from "../utils/encrypt";
import { sendResetSMS } from "../utils/smsService";
import { authenticateJWT } from "../middleware/authMiddleware"; // Your JWT auth middleware

const router = Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Utility function to validate and send errors
const handleValidationErrors = (req: Request, res: Response): boolean => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() });
    return true; // Return true if there are validation errors
  }
  return false; // Return false if there are no errors
};

// Google OAuth Callback Route
router.get(
  "/google/redirect",
  passport.authenticate("google"),
  (req: Request, res: Response): void => {
    if (!req.user) {
      res.status(400).json({ message: "Authentication failed, no user found" });
      return;
    }
    // Generate the JWT token from the authenticated user document
    const jwtToken = req.user.generateJwtToken();
    res.status(200).json({ token: jwtToken, user: req.user });
  }
);
// Register Route (Email/Password)
router.post(
  "/register",
  [
    body("email").isEmail().withMessage("Please enter a valid email"),
    body("password").isLength({ min: 7, max: 12 }).withMessage("Password must be between 7 to 12 characters"),
    body("confirmPassword").custom((value: string, { req }) => value === req.body.password).withMessage("Passwords must match"),
  ],
  async (req: Request, res: Response): Promise<void> => {
    if (handleValidationErrors(req, res)) return; // Handle validation errors

    const { email, phone, password }: UserSignup = req.body;

    try {
      const userExists = await User.findOne({ email });
      if (userExists) {
        res.status(400).json({ message: "User already exists" });
        return; // Early return after response
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser = new User({
        email,
        phone,
        password: hashedPassword,
      });

      await newUser.save();
      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Login Route (Email/Password or Google OAuth token)
router.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { emailOrPhone, password, googleToken } = req.body;
    let user;

    if (googleToken) {
      const ticket = await googleClient.verifyIdToken({
        idToken: googleToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        res.status(400).json({ message: "Invalid Google token" });
        return; // Early return after response
      }
      user = await User.findOne({ email: payload.email });
    } else {
      user = await User.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });

      if (!user || !(await bcrypt.compare(password, user.password || ''))) {
        res.status(400).json({ message: "Invalid credentials" });
        return; // Early return after response
      }
    }

    if (!user) {
      res.status(400).json({ message: "User not found" });
      return; // Early return after response
    }

    const token = user.generateJwtToken();
    res.json({ token }); // Respond with token
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error", error: (error as Error).message });
  }
});

// Refresh Token Route
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;
  try {
    const userData = authService.verifyRefreshToken(refreshToken);
    const newAccessToken = authService.createJwtToken(userData.userId);
    res.status(200).json({ newAccessToken });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// Forgot Password Route
router.post("/forgot-password", async (req: Request, res: Response): Promise<void> => {
  const { emailOrPhone } = req.body;

  try {
    const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return; // Early return after response
    }

    const resetToken = encryptUtils.generateRandomToken();
    
    // Ensure email or phone is defined
    let message: string;
    if (user.email === emailOrPhone) {
      await sendPasswordResetEmail(user.email!, resetToken); // Always assert that user.email is string here
      message = "Password reset email sent";
    } else if (user.phone === emailOrPhone) {
      if (!user.phone) {
        res.status(400).json({ message: "Phone number is required" });
        return; // Early return after response
      } else {
        await sendResetSMS(user.phone, resetToken);
        message = "Password reset SMS sent";
      }
    } else {
      res.status(400).json({ message: "User verification failed." });
      return;
    }

    res.json({ message });
  } catch (error) {
    console.error("Error during password reset request:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset Password Route
router.post("/reset-password", async (req: Request, res: Response): Promise<void> => {
  const { emailOrPhone, verificationCode, newPassword } = req.body;

  try {
    const decoded = jwt.verify(verificationCode, process.env.JWT_SECRET!) as UserTokenPayload;
    const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phone: emailOrPhone }] });

    if (!user) {
      res.status(400).json({ message: "Invalid token or user not found" });
      return; // Early return after response
    }

    user.password = await encryptUtils.hashPassword(newPassword);
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset Password Server Error:", error);
    res.status(500).json({ message: "Server error", error: error instanceof Error ? error.message : String(error) });
  }
});

// Protected profile route
router.get("/profile", authenticateJWT, (req: Request, res: Response): void => {
  res.status(200).json({ user: req.user });
});

// Logout Route
router.get("/logout", (req: Request, res: Response): void => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ message: 'Error logging out' });
    }
    res.redirect("/"); // Redirect to the home page after logout
  });
});

// Login Page Route
router.get("/login", (req: Request, res: Response): void => {
  if (req.user) {
    return res.redirect("/profile");
  }
  res.render("login"); // Render the login page if not authenticated
});

export default router;