import nodemailer, { type Transporter } from "nodemailer";
import { config, isProd } from "../config.js";
import { logger } from "./logger.js";

export interface Mail {
  to: string;
  subject: string;
  html: string;
  text: string;
}

/** True when real email can be sent (SMTP or Resend configured). */
export const mailConfigured = () => Boolean(config.SMTP_HOST || config.RESEND_API_KEY);

let smtp: Transporter | undefined;
const getSmtp = () =>
  (smtp ??= nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    secure: config.SMTP_PORT === 465, // 465 = TLS from the start; 587 upgrades with STARTTLS
    auth: { user: config.SMTP_USER, pass: config.SMTP_PASS },
  }));

// Transactional email: SMTP if configured, else Resend's HTTP API. With neither,
// non-production environments log the email instead of sending it.
export const sendMail = async (mail: Mail) => {
  if (config.SMTP_HOST) {
    await getSmtp().sendMail({ from: config.MAIL_FROM, ...mail });
    return;
  }

  if (!config.RESEND_API_KEY) {
    if (isProd) throw new Error("No SMTP_HOST or RESEND_API_KEY set; cannot send email");
    logger.info({ to: mail.to, subject: mail.subject }, `[mail:dev]\n${mail.text}`);
    return;
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: config.MAIL_FROM, ...mail }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Resend error ${res.status}: ${body.slice(0, 200)}`);
  }
};
