const mineflayer = require('mineflayer');
process.on('uncaughtException', (err) => {
  if (err.code === 'EPIPE') return;
  console.error(err);
});

const host = process.argv[2] || 'localhost';
const port = parseInt(process.argv[3]) || 25565;
const count = parseInt(process.argv[4]) || 10;
const duration = parseInt(process.argv[5]) || 30;
const version = process.argv[6] || false;

const usernames = [
  'xDark', 'ProCraft', 'ShadowPvP', 'NightMC', 'BlazeOP', 'StormYT',
  'FuryHD', 'CrystalTV', 'PixelPro', 'NovaX', 'ApexOP', 'ViperMC',
  'PhantomPVP', 'EliteCraft', 'ZenithHD', 'FrostyTV', 'InfernoOP',
  'TitanMC', 'OmegaX', 'RagePro', 'VenomYT', 'CyberHD', 'NitroTV',
  'AstraOP', 'LunarPVP', 'SolarCraft', 'CrimsonX', 'VoidHD', 'AxelOP',
  'DracoTV', 'FalconMC', 'WardenOP', 'HexaPro', 'KrakenYT', 'RavenHD',
  'StormPVP', 'BlitzCraft', 'GhostOP', 'ShadowTV', 'NebulaX',
  'DarkBot', 'CyberPunk', 'NightHawk', 'PhantomX', 'StealthOP',
];

const MAX_ATTEMPTS = 4;
const RETRY_DELAY = 2000;

function randomUsername() {
  const base = usernames[Math.floor(Math.random() * usernames.length)];
  const num = Math.floor(Math.random() * 100000);
  return `${base}_${num}`;
}

let connected = 0;
let finished = 0;
const start = Date.now();
const bots = new Map();

function createBot(index, attempt) {
  attempt = attempt || 0;
  const username = randomUsername();
  try {
    const opts = {
      host: host,
      port: port,
      username: username,
      auth: 'offline',
    };
    if (version) opts.version = version;

    const bot = mineflayer.createBot(opts);
    bot._darkie_idx = index;
    bot._darkie_attempt = attempt;
    bot._darkie_connected = false;
    bot._darkie_done = false;
    bots.set(index, bot);

    const connTimeout = setTimeout(() => {
      if (!bot._darkie_connected && !bot._darkie_done) {
        bot._darkie_done = true;
        try { bot.end(); } catch (e) {}
        retry(index, attempt);
      }
    }, 10000);

    bot.on('login', () => {
      bot._darkie_connected = true;
      clearTimeout(connTimeout);
      connected++;
    });

    const pwd = `bot${Math.floor(Math.random() * 100000)}`;

    bot.on('spawn', () => {
      setTimeout(() => {
        try {
          bot.chat(`/register ${pwd} ${pwd}`);
        } catch (e) {}
      }, 2000);
      setTimeout(() => {
        try {
          bot.setControlState('forward', true);
          setTimeout(() => {
            bot.setControlState('forward', false);
            bot.setControlState('jump', true);
            setTimeout(() => bot.setControlState('jump', false), 500);
          }, 2000);
        } catch (e) {}
      }, 3000);
    });

    bot.on('error', (err) => {
      clearTimeout(connTimeout);
      if (!bot._darkie_done) {
        bot._darkie_done = true;
        retry(index, attempt);
      }
    });

    bot.on('end', (reason) => {
      clearTimeout(connTimeout);
      if (bots.get(index) === bot) {
        bots.delete(index);
      }
      if (!bot._darkie_done) {
        bot._darkie_done = true;
        if (bot._darkie_connected) {
          finished++;
        } else {
          retry(index, attempt);
        }
      }
    });

    setTimeout(() => {
      try { bot.end(); } catch (e) {}
    }, duration * 1000);

  } catch (e) {
    retry(index, attempt);
  }
}

function retry(index, attempt) {
  if (attempt + 1 < MAX_ATTEMPTS) {
    setTimeout(() => createBot(index, attempt + 1), RETRY_DELAY);
  } else {
    finished++;
  }
}

// stagger connections — connect as fast as possible
const stagger = Math.max(1, Math.min(50, 250 / count));
for (let i = 0; i < count; i++) {
  setTimeout(() => createBot(i, 0), i * stagger);
}

// status reporting
let last_report = '';
const interval = setInterval(() => {
  const elapsed = ((Date.now() - start) / 1000).toFixed(0);
  const remaining = count - finished;
  const report = `  [MC] ${connected} connected | ${remaining} active | ${elapsed}s/${duration}s`;
  if (report !== last_report) {
    console.log(report);
    last_report = report;
  }
}, 1000);

setTimeout(() => {
  clearInterval(interval);
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\n  [MC] Done: ${connected} bots connected in ${elapsed}s`);
  bots.forEach(b => { try { b.end(); } catch (e) {} });
  bots.clear();
  process.exit(0);
}, (duration + 3) * 1000);

process.on('SIGINT', () => {
  clearInterval(interval);
  const remaining = count - finished;
  console.log(`\n  [MC] Interrupted: ${connected} connected, ${remaining} remaining`);
  bots.forEach(b => { try { b.end(); } catch (e) {} });
  bots.clear();
  process.exit(0);
});
