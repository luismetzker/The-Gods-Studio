'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const EMAIL_DIR = path.join(DATA_DIR, 'emails');

const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM =
  process.env.MAIL_FROM || (SMTP_USER ? `The Gods Studio <${SMTP_USER}>` : 'The Gods Studio <no-reply@thegods.studio>');

let transporter = null;
if (SMTP_HOST) {
  try {
    const nodemailer = require('nodemailer');
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    });
    console.log('[mailer] SMTP configurado (' + SMTP_HOST + ').');
  } catch (e) {
    console.warn('[mailer] nodemailer não encontrado; usando fallback de arquivo. Instale com: npm i nodemailer');
  }
} else {
  console.log('[mailer] SMTP não configurado. Usando fallback de arquivo (veja data/emails e o console).');
}

async function sendEmail({ to, subject, html, text }) {
  if (transporter) {
    try {
      await transporter.sendMail({ from: MAIL_FROM, to, subject, text: text || html, html });
      return { sent: true, dev: false };
    } catch (e) {
      console.error('[mailer] falha ao enviar via SMTP, usando fallback:', e && e.message);
    }
  }

  try {
    fs.mkdirSync(EMAIL_DIR, { recursive: true });
    const slug = (String(to) + '-' + String(subject)).replace(/[^a-z0-9]/gi, '_').slice(0, 70);
    const file = path.join(EMAIL_DIR, slug + '-' + Date.now() + '.html');
    fs.writeFileSync(file, html);
    console.log('\n========== [mailer] EMAIL (modo dev) ==========');
    console.log('Para : ' + to);
    console.log('Assunto: ' + subject);
    console.log('Arquivo: ' + file);
    console.log('=================================================\n');
  } catch (e) {
    console.error('[mailer] falha no fallback de arquivo:', e && e.message);
  }
  return { sent: false, dev: true };
}

module.exports = { sendEmail, MAIL_FROM };
