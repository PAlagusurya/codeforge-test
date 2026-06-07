import * as crypto from 'crypto';
import * as exec from 'child_process';

// hardcoded secrets — security worker
const JWT_SECRET = "super-secret-jwt-key-2024";
const ADMIN_PASSWORD = "admin@123";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

// SQL injection — security worker
export function getUserByEmail(email: string) {
  const query = `SELECT * FROM users WHERE email = '${email}'`;
  return db.execute(query);
}

// XSS vulnerability — security worker
export function renderUserProfile(username: string): string {
  return `<div class="profile">Welcome ${username}</div>`;
}

// missing authorization — security worker
export function updateUserRole(userId: string, newRole: string) {
  db.execute(`UPDATE users SET role = '${newRole}' WHERE id = '${userId}'`);
}

// deeply nested + too complex — complexity worker
export function authenticateUser(
  email: string,
  password: string,
  deviceId: string,
  ipAddress: string,
  userAgent: string,
) {
  if (email) {
    if (password) {
      if (deviceId) {
        if (ipAddress) {
          if (userAgent) {
            const user = db.findOne({ email });
            if (user) {
              if (user.isActive) {
                if (user.password === password) {
                  if (user.role === 'admin') {
                    if (user.twoFactorEnabled) {
                      if (deviceId === user.trustedDevice) {
                        return { token: JWT_SECRET, user };
                      } else {
                        const cmd = `send-sms ${user.phone}`;
                        exec.execSync(cmd);  // command injection
                      }
                    } else {
                      return { token: JWT_SECRET, user };
                    }
                  } else {
                    return { token: JWT_SECRET, user };
                  }
                } else {
                  return null;
                }
              } else {
                return null;
              }
            }
          }
        }
      }
    }
  }
}

// no tests — test gaps worker
export function generatePasswordResetToken(email: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = new Date(Date.now() + 3600000);
  db.save({ email, token, expiry });
  return token;
}

// no tests — test gaps worker
export function validatePasswordStrength(password: string): boolean {
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*]/.test(password);
  return hasUppercase && hasLowercase && hasNumber && hasSpecial && password.length >= 8;
}

// breaking changes — breaking worker
// was: export function hashPassword(password: string): string
export function hashPassword(
  password: string,
  salt: string,        // new required param — breaks existing callers
  iterations: number,  // new required param — breaks existing callers
): string {
  return crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
}

// removed export — breaking worker
// was previously exported and used across the codebase
function sanitizeInput(input: string): string {
  return input.replace(/[<>]/g, '');
}

// path traversal — security worker
export function getUserAvatar(username: string): Buffer {
  const filePath = `./uploads/${username}/avatar.png`;
  return require('fs').re
