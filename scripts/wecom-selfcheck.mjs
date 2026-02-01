import fs from 'node:fs';
import path from 'node:path';

const required = [
  'WECOM_CORP_ID',
  'WECOM_AGENT_ID',
  'WECOM_CORP_SECRET',
  'WECOM_CALLBACK_TOKEN',
  'WECOM_CALLBACK_AES_KEY',
];

const optional = [
  'WECOM_WEBHOOK_PATH',
];

const missing = required.filter(k => !process.env[k]);
console.log('WeCom plugin self-check');
console.log('----------------------');
console.log('required ok:', required.length - missing.length, '/', required.length);
if (missing.length) {
  console.log('missing required env:');
  for (const k of missing) console.log(' -', k);
  process.exitCode = 1;
}

for (const k of optional) {
  if (process.env[k]) console.log('optional', k, '=', process.env[k]);
}

// quick file existence checks
const pluginEntry = path.resolve('src/index.js');
console.log('plugin entry:', pluginEntry, fs.existsSync(pluginEntry) ? 'OK' : 'MISSING');

console.log('
Tip: run with a loaded env file, e.g.');
console.log('  export $(cat .env | xargs) && node scripts/wecom-selfcheck.mjs');
