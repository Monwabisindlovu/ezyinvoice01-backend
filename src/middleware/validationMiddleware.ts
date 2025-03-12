import { check, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const validateRegister = [
  check('email').isEmail().withMessage('Please enter a valid email'),
  check('phone').isMobilePhone('any').optional().withMessage('Please enter a valid phone number'),
  check('password')
    .isLength({ min: 7, max: 12 })
    .withMessage('Password must be between 7 to 12 characters')
];

export const validateConfirmPassword = [
  check('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords must match');
      }
      return true;
    })
];

export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array()); // Log validation errors
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};