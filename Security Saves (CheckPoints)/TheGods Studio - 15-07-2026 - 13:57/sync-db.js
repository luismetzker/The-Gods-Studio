'use strict';

require('dotenv').config();

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

const SERVER = (process.env.SYNC_SERVER || '').replace(/\/+$/, '');
const TOKEN = process.env.DB_SYNC_TOKEN || '';
const LOCAL_DIR = process.env.SYNC_LOCAL_DIR || path.join(__dirname, 'db-backup');
const LOCAL_FILE = path.join(LOCAL_DIR, 'accounts.db');
const INTERVAL_MS = 5 * 60 * 1000;

if (!SERVER || !TOKEN) {
  console.error('Defina SYNC_SERVER (ex: https://the-gods-studio.onrender.com) e DB_SYNC_TOKEN no .env ou ambiente.');
  process.exit(1);
}

async function pullFromServer() {
  await fsp.mkdir(LOCAL_DIR, { recursive: true });
  const tmp = LOCAL_FILE + '.tmp';
  const res = await fetch(SERVER + '/api/db-backup?token=' + encodeURIComponent(TOKEN));
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length < 100) throw new Error('arquivo suspeito (' + buf.length + ' bytes)');
  await fsp.writeFile(tmp, buf);
  await fsp.rm(LOCAL_FILE, { force: true });
  await fsp.rename(tmp, LOCAL_FILE);
  return buf.length;
}

async function pushToServer() {
  const buf = await fsp.readFile(LOCAL_FILE);
  const res = await fetch(SERVER + '/api/db-backup?token=' + encodeURIComponent(TOKEN), {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'X-Requested-With': 'xmlhttprequest' },
    body: buf,
  });
  if (!res.ok) throw new Error('push HTTP ' + res.status);
  return true;
}

async function syncOnce() {
  const bytes = await pullFromServer();
  console.log(new Date().toISOString(), 'backup baixado:', bytes, 'bytes ->', LOCAL_FILE);

  try {
    const info = await fetch(SERVER + '/api/db-info?token=' + encodeURIComponent(TOKEN));
    if (info.ok) {
      const data = await info.json();
      if (data.users === 0) {
        await pushToServer();
        console.log(new Date().toISOString(), 'servidor vazio: cópia local restaurada no servidor.');
      }
    }
  } catch (_) {}
}

async function loop() {
  try {
    await syncOnce();
  } catch (e) {
    console.error(new Date().toISOString(), 'falha na sincronização:', e.message, '(retry em 5 min)');
  }
  setTimeout(loop, INTERVAL_MS);
}

loop();
