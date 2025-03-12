"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleValidationErrors = exports.validateConfirmPassword = exports.validateRegister = void 0;
const express_validator_1 = require("express-validator");
exports.validateRegister = [
    (0, express_validator_1.check)('email').isEmail().withMessage('Please enter a valid email'),
    (0, express_validator_1.check)('phone').isMobilePhone('any').optional().withMessage('Please enter a valid phone number'),
    (0, express_validator_1.check)('password')
        .isLength({ min: 7, max: 12 })
        .withMessage('Password must be between 7 to 12 characters')
];
exports.validateConfirmPassword = [
    (0, express_validator_1.check)('confirmPassword')
        .custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords must match');
        }
        return true;
    })
];
const handleValidationErrors = (req, res, next) => {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        console.log('Validation Errors:', errors.array()); // Log validation errors
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};
exports.handleValidationErrors = handleValidationErrors;
