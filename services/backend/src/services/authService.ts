import crypto from "crypto";
import nodemailer from "nodemailer";
import db from "../db";
import { User, UserRow } from "../types/user";
import jwtUtils from "../utils/jwt";
import ejs from "ejs";

const RESET_TTL = 1000 * 60 * 60; // 1 hora
const INVITE_TTL = 1000 * 60 * 60 * 24 * 7; // 7 días

/**
 * Escapa caracteres HTML especiales
 * Sirve para evitar que se cuele código malicioso (XSS / Template Injection)
 * (Ésta es la solución que propusimos como posible mitigación en el práctico 2)
 */
function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

class AuthService {
  static async createUser(user: User) {
    // Revisamos si ya hay alguien con el mismo usuario o mail
    const existing = await db<UserRow>("users")
      .where({ username: user.username })
      .orWhere({ email: user.email })
      .first();
    if (existing)
      throw new Error("Ya existe un usuario con ese nombre o correo");

    // Generamos el token de invitación
    const invite_token = crypto.randomBytes(6).toString("hex");
    const invite_token_expires = new Date(Date.now() + INVITE_TTL);
    await db<UserRow>("users").insert({
      username: user.username,
      password: user.password,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      invite_token,
      invite_token_expires,
      activated: false,
    });

    // Armamos el transporte de correo (usa el SMTP local)
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const link = `${process.env.FRONTEND_URL}/activate-user?token=${invite_token}&username=${user.username}`;

    // Mitigación: escapamos los nombres antes de ponerlos en el HTML
    const safeFirstName = escapeHtml(user.first_name);
    const safeLastName = escapeHtml(user.last_name);

    const template = `
      <html>
        <body>
          <h1>Hola ${safeFirstName} ${safeLastName}</h1>
          <p>Hacé clic <a href="${link}">acá</a> para activar tu cuenta.</p>
        </body>
      </html>`;
    const htmlBody = ejs.render(template);

    await transporter.sendMail({
      from: "info@example.com",
      to: user.email,
      subject: "Activá tu cuenta",
      html: htmlBody,
    });
  }

  static async updateUser(user: User) {
    const existing = await db<UserRow>("users").where({ id: user.id }).first();
    if (!existing) throw new Error("No se encontró el usuario");

    await db<UserRow>("users").where({ id: user.id }).update({
      username: user.username,
      password: user.password,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
    });

    return existing;
  }

  static async authenticate(username: string, password: string) {
    const user = await db<UserRow>("users")
      .where({ username })
      .andWhere("activated", true)
      .first();

    if (!user) throw new Error("Usuario inválido o no activado");
    if (password != user.password) throw new Error("Contraseña incorrecta");

    return user;
  }

  static async sendResetPasswordEmail(email: string) {
    const user = await db<UserRow>("users")
      .where({ email })
      .andWhere("activated", true)
      .first();

    if (!user)
      throw new Error("No hay usuario con ese mail o no está activado");

    const token = crypto.randomBytes(6).toString("hex");
    const expires = new Date(Date.now() + RESET_TTL);

    await db("users").where({ id: user.id }).update({
      reset_password_token: token,
      reset_password_expires: expires,
    });

    // Enviamos el correo con el link para resetear la contraseña
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || "587"),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      to: user.email,
      subject: "Link para resetear tu contraseña",
      html: `Hacé clic <a href="${link}">acá</a> para cambiar tu contraseña.`,
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    const row = await db<UserRow>("users")
      .where("reset_password_token", token)
      .andWhere("reset_password_expires", ">", new Date())
      .first();

    if (!row) throw new Error("Token inválido o vencido");

    await db("users").where({ id: row.id }).update({
      password: newPassword,
      reset_password_token: null,
      reset_password_expires: null,
    });
  }

  static async setPassword(token: string, newPassword: string) {
    const row = await db<UserRow>("users")
      .where("invite_token", token)
      .andWhere("invite_token_expires", ">", new Date())
      .first();

    if (!row) throw new Error("Token de invitación inválido o vencido");

    await db("users")
      .update({
        password: newPassword,
        invite_token: null,
        invite_token_expires: null,
        activated: true,
      })
      .where({ id: row.id });
  }

  static generateJwt(userId: string): string {
    return jwtUtils.generateToken(userId);
  }
}

export default AuthService;
