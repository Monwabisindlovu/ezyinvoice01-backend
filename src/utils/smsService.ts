import twilio from 'twilio';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = twilio(accountSid, authToken);

// Function to send a reset password SMS using Twilio
export const sendResetSMS = async (phone: string, token: string): Promise<void> => {
  const message = `Use this token to reset your password: ${token}`;
  await client.messages.create({
    body: message,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone,
  });
};