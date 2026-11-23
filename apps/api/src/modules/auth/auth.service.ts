import bcrypt from "bcrypt";
import crypto from "node:crypto";
import validator from "validator";
import { config } from "../../config.js";
import { AppError, badRequest, conflict, unauthorized } from "../../lib/errors.js";
import { mailConfigured, sendMail } from "../../lib/mailer.js";
import { User, type UserDoc } from "../../models/user.js";
import type { LoginInput, RegisterInput, ResetPasswordInput, VerifyEmailInput } from "./auth.schemas.js";

const BCRYPT_ROUNDS = 10;
const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const OTP_FIELDS = "+otpHash +otpExpires +otpAttempts +otpSentAt";

const hashToken = (token: string) => crypto.createHash("sha256").update(token).digest("hex");
// Keyed, so a leaked database can't be brute-forced back to 6-digit codes offline.
const hashOtp = (code: string) => crypto.createHmac("sha256", config.JWT_KEY).update(code).digest("hex");

const badCode = () => badRequest("That code is wrong or has expired", "invalid_code");

/** Emails a fresh 6-digit code, replacing any earlier one. */
const sendOtp = async (user: UserDoc) => {
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
  user.otpHash = hashOtp(code);
  user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
  user.otpAttempts = 0;
  user.otpSentAt = new Date();
  await user.save();
  await sendMail({
    to: user.email,
    subject: `${code} is your Araxys verification code`,
    text: `Hi ${user.fullName},\n\nYour Araxys verification code is ${code}. It expires in 10 minutes.\n\nIf you didn't sign up, ignore this email.`,
    html: `<p>Hi ${validator.escape(user.fullName)},</p><p>Your Araxys verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${code}</p><p>It expires in 10 minutes. If you didn't sign up, ignore this email.</p>`,
  });
};

const canResend = (user: UserDoc) => !user.otpSentAt || Date.now() - user.otpSentAt.getTime() >= OTP_RESEND_MS;

export const authService = {
  async login({ email, password }: LoginInput): Promise<UserDoc> {
    const user = await User.findOne({ email }).select(OTP_FIELDS);
    if (!user || !(await user.isPasswordCorrect(password))) {
      throw unauthorized("Invalid email or password");
    }
    if (user.emailVerified === false) {
      if (canResend(user)) await sendOtp(user);
      throw new AppError(403, "Verify your email first. We sent a code to your inbox.", "email_unverified");
    }
    return user;
  },

  /** Without email configured, accounts are verified straight away (old behaviour). */
  async register(input: RegisterInput): Promise<UserDoc> {
    if (await User.exists({ email: input.email })) throw conflict("Email already exists");
    const verify = mailConfigured();
    const user = await User.create({
      ...input,
      password: await bcrypt.hash(input.password, BCRYPT_ROUNDS),
      ...(verify && { emailVerified: false }),
    });
    if (verify) await sendOtp(user);
    return user;
  },

  async verifyEmail({ email, code }: VerifyEmailInput): Promise<UserDoc> {
    const user = await User.findOne({ email }).select(OTP_FIELDS);
    if (!user || user.emailVerified !== false || !user.otpHash || !user.otpExpires) throw badCode();
    if (user.otpExpires < new Date() || (user.otpAttempts ?? 0) >= OTP_MAX_ATTEMPTS) {
      throw badRequest("That code has expired. Send a new one.", "invalid_code");
    }
    const ok = crypto.timingSafeEqual(Buffer.from(hashOtp(code)), Buffer.from(user.otpHash));
    if (!ok) {
      // Atomic, so parallel guesses can't share one attempt.
      await User.updateOne({ _id: user._id }, { $inc: { otpAttempts: 1 } });
      throw badCode();
    }
    user.emailVerified = true;
    user.otpHash = user.otpExpires = user.otpAttempts = user.otpSentAt = undefined;
    return user.save();
  },

  /** Silently does nothing for unknown/verified emails or within the resend cooldown. */
  async resendCode(email: string) {
    const user = await User.findOne({ email }).select(OTP_FIELDS);
    if (user?.emailVerified === false && canResend(user)) await sendOtp(user);
  },

  /** Emails a one-time link. Silently does nothing for unknown emails. */
  async requestPasswordReset(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();
    if (!validator.isEmail(email)) return;

    const user = await User.findOne({ email });
    if (!user) return;

    const token = crypto.randomBytes(32).toString("hex");
    user.resetTokenHash = hashToken(token);
    user.resetTokenExpires = new Date(Date.now() + RESET_TOKEN_TTL_MS);
    await user.save();

    const link = `${config.APP_URL.replace(/\/$/, "")}/reset-password?token=${token}`;
    await sendMail({
      to: user.email,
      subject: "Reset your Araxys password",
      text: `Hi ${user.fullName},\n\nReset your password here (valid for 30 minutes):\n${link}\n\nIf you didn't ask for this, ignore this email.`,
      html: `<p>Hi ${validator.escape(user.fullName)},</p><p><a href="${link}">Reset your password</a> (valid for 30 minutes).</p><p>If you didn't ask for this, ignore this email.</p>`,
    });
  },

  async resetPassword({ token, newPassword }: ResetPasswordInput) {
    const user = await User.findOne({
      resetTokenHash: hashToken(token),
      resetTokenExpires: { $gt: new Date() },
    });
    if (!user) throw badRequest("This reset link is invalid or has expired", "invalid_token");

    user.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    user.passwordChangedAt = new Date(); // signs out every existing session
    user.resetTokenHash = undefined;
    user.resetTokenExpires = undefined;
    user.emailVerified = true; // the emailed link proves they own the address
    await user.save();
  },
};
