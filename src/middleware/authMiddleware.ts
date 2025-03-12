import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User';

// Extend Express Request type to include user
declare module 'express' {
  interface Request {
    user?: any; // Define a more specific type based on your user model
  }
}

/**
 * Middleware to authenticate JWT
 */
export const authenticateJWT = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token

  if (!token) {
    res.status(401).json({ message: 'Unauthorized: No token provided' });
    return; // ✅ Simply return instead of casting to void
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string }; // Verify token and extract userId
    const user = await User.findById(decoded.userId).select('-password'); // Select user excluding password

    if (!user) {
      res.status(401).json({ message: 'Unauthorized: User not found' });
      return; // ✅ Just return instead of casting to void
    }

    req.user = user; // Attach user to request object
    next(); // Move to the next middleware
  } catch (error) {
    res.status(403).json({ message: 'Forbidden: Invalid token' });
    return; // ✅ Simply return instead of casting to void
  }
};

/**
 * Middleware to authorize user roles
 */
export const authorizeRoles = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
      return; // ✅ Simply return instead of casting to void
    }
    next(); // Continue if authorized
  };
};

export default { authenticateJWT, authorizeRoles };