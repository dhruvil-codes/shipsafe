import { fileURLToPath } from 'node:url';
import { resolve, dirname, join } from 'node:path';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
if(!process.env.INSTABOX_API_KEY || !process.env.INSTABOX_SANDBOX_ID) {
  console.error('Set INSTABOX_API_KEY and INSTABOX_SANDBOX_ID in the ignored root .env.local before starting the scan worker.');
  process.exit(1);
}
const port=process.env.SHIPSAFE_PORT ?? '3016';
if(!/^\d{2,5}$/.test(port) || Number(port)>65535) throw new Error('Invalid SHIPSAFE_PORT');
const production=process.argv.includes('--production');
const proc=Bun.spawn(['bun',join(root,'apps/web/node_modules/next/dist/bin/next'),production?'start':'dev','-H','127.0.0.1','-p',port],{
  cwd:join(root,'apps/web'),
  env:{...process.env,NODE_ENV:production?'production':'development',SHIPSAFE_RUNTIME:'local',SHIPSAFE_LAB_ENABLED:'1',SHIPSAFE_DATA_DIR:process.env.SHIPSAFE_DATA_DIR ?? join(root,'.artifacts/local-scans')},
  stdin:'inherit',stdout:'inherit',stderr:'inherit'
});
process.exit(await proc.exited);
