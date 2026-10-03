import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCallback);
const password = process.argv[2];
if (!password || password.length < 12) {
  console.error('استخدم كلمة مرور لا تقل عن 12 حرفًا: npm run admin:hash -- "كلمة-مرور-قوية"');
  process.exit(1);
}
const salt = randomBytes(16);
const key = await scrypt(password, salt, 64);
console.log(`scrypt$${salt.toString('base64url')}$${Buffer.from(key).toString('base64url')}`);
