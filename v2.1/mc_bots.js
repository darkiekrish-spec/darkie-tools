const mineflayer = require('mineflayer');

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

function randomUsername() {
  const base = usernames[Math.floor(Math.random() * usernames.length)];
  const num = Math.floor(Math.random() * 10000);
  return `${base}_${num}`;
}

let connected = 0;
let failed = 0;
let disconnected = 0;
let botCount = 0;
const start = Date.now();
const bots = [];
const MAX_RETRIES = 2;

function createBot(index) {
  const username = randomUsername();
  const attempt = arguments[1] || 0;
  try {
    const opts = {
      host: host,
      port: port,
      username: username,
      auth: 'offline',
      hideErrors: false,
    };
    if (version) opts.version = version;

    const bot = mineflayer.createBot(opts);
    bot._darkie_idx = index;
    bot._darkie_attempt = attempt;
    bots.push(bot);

    bot.on('login', () => {
      connected++;
    });

    bot.on('spawn', () => {
      setTimeout(() => {
        try {
          bot.setControlState('forward', true);
          setTimeout(() => {
            bot.setControlState('forward', false);
            bot.setControlState('jump', true);
            setTimeout(() => bot.setControlState('jump', false), 500);
          }, 2000);
        } catch(e) {}
      }, 1000);
    });

    bot.on('error', (err) => {
      if (attempt < MAX_RETRIES) {
        setTimeout(() => createBot(index, attempt + 1), 2000);
      } else {
        failed++;
      }
    });

    bot.on('end', (reason) => {
      disconnected++;
    });

    setTimeout(() => {
      try { bot.end(); } catch(e) {}
    }, duration * 1000);

  } catch(e) {
    if (attempt < MAX_RETRIES) {
      setTimeout(() => createBot(index, attempt + 1), 2000);
    } else {
      failed++;
    }
  }
}

// stagger connections — connect quickly, not spread across duration
const stagger = Math.max(50, Math.min(200, 1000 / count));
for (let i = 0; i < count; i++) {
  setTimeout(() => createBot(i), i * stagger);
}

// status reporting
let last_report = '';
const interval = setInterval(() => {
  const elapsed = ((Date.now() - start) / 1000).toFixed(0);
  const report = `  [MC] ${connected} connected | ${failed} failed | ${disconnected} left | ${elapsed}s/${duration}s`;
  if (report !== last_report) {
    console.log(report);
    last_report = report;
  }
}, 1000);

setTimeout(() => {
  clearInterval(interval);
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\n  [MC] Done: ${connected} bots connected in ${elapsed}s`);
  bots.forEach(b => { try { b.end(); } catch(e) {} });
  process.exit(0);
}, (duration + 3) * 1000);

process.on('SIGINT', () => {
  clearInterval(interval);
  console.log(`\n  [MC] Interrupted: ${connected} bots`);
  bots.forEach(b => { try { b.end(); } catch(e) {} });
  process.exit(0);
});
