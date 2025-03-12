"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendPasswordResetEmail = exports.sendEmail = void 0;
const nodemailer_1 = __importDefault(require("nodemailer"));
// Email configuration (adjust this to your email service provider)
const transporter = nodemailer_1.default.createTransport({
    service: 'gmail', // Can be any email service like Gmail, SendGrid, etc.
    auth: {
        user: process.env.SMTP_USER, // Use environment variables for sensitive data
        pass: process.env.SMTP_PASS, // Make sure to store this in a secure place
    },
});
// Function to send an email
const sendEmail = (to, subject, text, html) => __awaiter(void 0, void 0, void 0, function* () {
    const mailOptions = {
        from: process.env.SMTP_USER, // Sender email (use environment variable)
        to, // Recipient email
        subject, // Email subject
        text, // Plain text body
        html, // HTML formatted body (can include links, styling, etc.)
    };
    try {
        // Send the email
        const info = yield transporter.sendMail(mailOptions);
        console.log('Email sent: ' + info.response);
        return info;
    }
    catch (error) {
        console.error('Error sending email: ', error);
        throw new Error('Email sending failed'); // Provide clear error messaging
    }
});
exports.sendEmail = sendEmail;
// Function to send a password reset email
const sendPasswordResetEmail = (to, resetToken) => __awaiter(void 0, void 0, void 0, function* () {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const subject = 'Password Reset Request';
    const text = `You requested a password reset. Please click the following link to reset your password: ${resetLink}`;
    const html = `
    <p>You requested a password reset. Please click the following link to reset your password:</p>
    <a href="${resetLink}">Reset Password</a>
  `;
    try {
        // Call the sendEmail function to send the reset email
        yield (0, exports.sendEmail)(to, subject, text, html);
    }
    catch (error) {
        console.error('Error sending password reset email: ', error);
        throw new Error('Password reset email failed');
    }
});
exports.sendPasswordResetEmail = sendPasswordResetEmail;
// Default export containing all functions
exports.default = exports.sendPasswordResetEmail;
