import bcrypt from 'bcryptjs';  // Only use bcryptjs, not bcrypt

import crypto from 'crypto';

// Hash password before storing it in the database
export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(12);
  return await bcrypt.hash(password, salt);
};

// Compare entered password with stored hashed password
export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword); // Use bcrypt's compare function directly
};

// Function to generate a random token (for encryption, reset tokens, etc.)
export const generateRandomToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

// Function to encrypt data using AES-256-CBC
export const encryptData = (data: string, secretKey: string): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
};

// Function to decrypt data using AES-256-CBC
export const decryptData = (encryptedData: string, secretKey: string): string => {
  const [ivHex, encrypted] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Default export containing all functions
export default {
  hashPassword,
  comparePassword,
  generateRandomToken,
  encryptData,
  decryptData,
};