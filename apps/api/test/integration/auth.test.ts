import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

// Capture outgoing email so the test can read the reset link.
const { sent, mail } = vi.hoisted(() => ({
  sent: [] as { to: string; text: string }[],
  mail: { on: false }, // flips email verification on for the OTP tests
}));
vi.mock("../../src/lib/mailer.js", () => ({
  sendMail: vi.fn(async (m: { to: string; text: string }) => void sent.push(m)),
  mailConfigured: () => mail.on,
}));

const { createApp } = await import("../../src/app.js");
const { clearDb, startDb, stopDb } = await import("../helpers/db.js");
const { signUp } = await import("../helpers/users.js");

const app = createApp();

beforeAll(startDb);
afterEach(async () => {
  sent.length = 0;
  await clearDb();
});
afterAll(stopDb);

describe("register + login", () => {
  it("registers, sets an httpOnly session cookie, and never returns the hash", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ fullName: "Ada Lovelace", email: "ADA@Example.com", password: "password123" })
      .expect(201);
    const cookie = String(res.headers["set-cookie"]);
    expect(cookie).toMatch(/token=/);
    expect(cookie).toMatch(/HttpOnly/i);

    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "ada@example.com", password: "password123" })
      .expect(200);
    expect(login.body.email).toBe("ada@example.com");
    expect(login.body.password).toBeUndefined();
  });

  it("rejects a wrong password with a generic message", async () => {
    const { email } = await signUp(app);
    const res = await request(app).post("/api/auth/login").send({ email, password: "wrongpass1" }).expect(401);
    expect(res.body.message).toBe("Invalid email or password");
  });

  it("rejects a duplicate email", async () => {
    const { email } = await signUp(app);
    await request(app)
      .post("/api/auth/register")
      .send({ fullName: "Copy Cat", email, password: "password123" })
      .expect(409);
  });

  it("profile never exposes the password hash", async () => {
    const { profile } = await signUp(app);
    expect(profile.password).toBeUndefined();
    expect(profile.resetTokenHash).toBeUndefined();
  });
});

describe("password reset", () => {
  it("answers the same for unknown emails and sends nothing", async () => {
    const res = await request(app).post("/api/auth/forgot-password").send({ email: "ghost@example.com" }).expect(200);
    expect(res.body.message).toMatch(/If an account exists/);
    expect(sent).toHaveLength(0);
  });

  it("resets with the emailed token, once, and signs out old sessions", async () => {
    const { agent, email } = await signUp(app);
    await request(app).post("/api/auth/forgot-password").send({ email }).expect(200);
    expect(sent).toHaveLength(1);
    const token = /token=([a-f0-9]{64})/.exec(sent[0]!.text)?.[1];
    expect(token).toBeDefined();

    // Make sure the reset lands in a later second than the original login.
    await new Promise((r) => setTimeout(r, 1100));
    await request(app).post("/api/auth/reset-password").send({ token, newPassword: "newpassword9" }).expect(200);

    // Old session is revoked.
    await agent.get("/api/profile/profile").expect(401);
    // Token is single-use.
    await request(app).post("/api/auth/reset-password").send({ token, newPassword: "another123" }).expect(400);
    // New password works, old one doesn't.
    await request(app).post("/api/auth/login").send({ email, password: "newpassword9" }).expect(200);
    await request(app).post("/api/auth/login").send({ email, password: "password123" }).expect(401);
  });

  it("the old team-code reset no longer works", async () => {
    const { email } = await signUp(app);
    await request(app)
      .post("/api/auth/reset-password")
      .send({ email, teamCode: "11111111", newPassword: "hijacked123" })
      .expect(400);
  });
});

describe("email verification (OTP)", () => {
  const codeIn = (i = sent.length - 1) => /code is (\d{6})/.exec(sent[i]!.text)?.[1];
  const register = (email = "otp@example.com") =>
    request(app).post("/api/auth/register").send({ fullName: "Otp User", email, password: "password123" });

  beforeEach(() => void (mail.on = true));
  afterEach(() => void (mail.on = false));

  it("registers without a session, emails a code, and the code signs you in once", async () => {
    const res = await register().expect(201);
    expect(res.body).toMatchObject({ verify: true, email: "otp@example.com" });
    expect(String(res.headers["set-cookie"] ?? "")).not.toMatch(/token=/);
    expect(sent).toHaveLength(1);
    const code = codeIn()!;

    // Login is blocked until verified.
    const blocked = await request(app).post("/api/auth/login").send({ email: "otp@example.com", password: "password123" }).expect(403);
    expect(blocked.body.code).toBe("email_unverified");

    const agent = request.agent(app);
    const ok = await agent.post("/api/auth/verify-email").send({ email: "otp@example.com", code }).expect(200);
    expect(ok.body.otpHash).toBeUndefined();
    await agent.get("/api/profile/profile").expect(200);

    // Single use; login now works.
    await request(app).post("/api/auth/verify-email").send({ email: "otp@example.com", code }).expect(400);
    await request(app).post("/api/auth/login").send({ email: "otp@example.com", password: "password123" }).expect(200);
  });

  it("locks the code after 5 wrong tries", async () => {
    await register().expect(201);
    const code = codeIn()!;
    const wrong = code === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) {
      await request(app).post("/api/auth/verify-email").send({ email: "otp@example.com", code: wrong }).expect(400);
    }
    await request(app).post("/api/auth/verify-email").send({ email: "otp@example.com", code }).expect(400);
  });

  it("resend respects the 60s cooldown and never reveals accounts", async () => {
    await register().expect(201);
    await request(app).post("/api/auth/resend-code").send({ email: "otp@example.com" }).expect(200);
    await request(app).post("/api/auth/resend-code").send({ email: "ghost@example.com" }).expect(200);
    expect(sent).toHaveLength(1); // only the signup email
  });

  it("rejects a malformed code", async () => {
    await register().expect(201);
    await request(app).post("/api/auth/verify-email").send({ email: "otp@example.com", code: "12ab" }).expect(400);
  });
});

describe("logout", () => {
  it("clears the session cookie", async () => {
    const { agent } = await signUp(app);
    await agent.post("/api/auth/logout").expect(200);
    await agent.get("/api/profile/profile").expect(401);
  });
});
