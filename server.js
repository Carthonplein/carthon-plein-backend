const express = require("express");
const cors = require("cors");
const tmi = require("tmi.js");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "change-me";

const GRID_SIZE = 4;
const TOTAL_NUMBERS = 75;

// ---------- Génération de carton (même algorithme que le prototype) ----------
function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed) {
  let a = seed;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seededShuffle(arr, rng) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function generateCard(seedStr) {
  const rng = mulberry32(hashString(seedStr));
  const pool = [];
  for (let n = 1; n <= TOTAL_NUMBERS; n++) pool.push(n);
  const picked = seededShuffle(pool, rng).slice(0, GRID_SIZE * GRID_SIZE);
  const grid = [];
  for (let row = 0; row < GRID_SIZE; row++) {
    const rowVals = [];
    for (let col = 0; col < GRID_SIZE; col++) rowVals.push(picked[col * GRID_SIZE + row]);
    grid.push(rowVals);
  }
  return grid;
}

function columnStatus(grid, drawnSet) {
  const cols = [];
  for (let c = 0; c < GRID_SIZE; c++) {
    let complete = true;
    for (let r = 0; r < GRID_SIZE; r++) {
      if (!drawnSet.has(grid[r][c])) {
        complete = false;
        break;
      }
    }
    cols.push(complete);
  }
  const count = cols.filter(Boolean).length;
  return { cols, count, blackout: count === GRID_SIZE };
}

// ---------- État de la partie, en mémoire ----------
let state = {
  drawn: [],
  players: [], // { pseudo, isSub }
  tierWinners: { 1: null, 2: null, 3: null },
  winner: null, // { pseudo, cardType }
  started: false, // devient true dès le premier clic sur "Nouvelle partie" (rend l'overlay visible aux viewers)
};

function gamePhase() {
  if (state.winner) return "finished";
  if (state.drawn.length > 0) return "playing";
  return "lobby";
}

function computeEntrants() {
  const entrants = [];
  for (const p of state.players) {
    entrants.push({ pseudo: p.pseudo, cardType: "principal", grid: generateCard(p.pseudo) });
    if (p.isSub) entrants.push({ pseudo: p.pseudo, cardType: "bonus", grid: generateCard(p.pseudo + "#sub") });
  }
  return entrants;
}

function computeLeaderboard(drawnSet) {
  const bestByPseudo = new Map();
  for (const p of state.players) {
    const cards = [{ cardType: "principal", grid: generateCard(p.pseudo) }];
    if (p.isSub) cards.push({ cardType: "bonus", grid: generateCard(p.pseudo + "#sub") });
    for (const c of cards) {
      const status = columnStatus(c.grid, drawnSet);
      const marked = c.grid.flat().filter((v) => drawnSet.has(v)).length;
      const remaining = GRID_SIZE * GRID_SIZE - marked;
      const current = bestByPseudo.get(p.pseudo);
      const better =
        !current || status.count > current.count || (status.count === current.count && remaining < current.remaining);
      if (better) bestByPseudo.set(p.pseudo, { pseudo: p.pseudo, cardType: c.cardType, count: status.count, remaining });
    }
  }
  return [...bestByPseudo.values()].sort((a, b) => b.count - a.count || a.remaining - b.remaining).slice(0, 3);
}

function refreshTiersAndWinner() {
  if (state.winner) return;
  const drawnSet = new Set(state.drawn);
  const entrants = computeEntrants();
  for (let level = 1; level <= GRID_SIZE - 1; level++) {
    if (state.tierWinners[level]) continue;
    const found = entrants.find((e) => columnStatus(e.grid, drawnSet).count >= level);
    if (found) state.tierWinners[level] = { pseudo: found.pseudo, cardType: found.cardType };
  }
  const finalWinner = entrants.find((e) => columnStatus(e.grid, drawnSet).blackout);
  if (finalWinner) state.winner = { pseudo: finalWinner.pseudo, cardType: finalWinner.cardType };
}

function checkAdmin(req, res) {
  if (req.body?.adminKey !== ADMIN_KEY) {
    res.status(401).json({ error: "clé admin invalide" });
    return false;
  }
  return true;
}

// Inscription partagée entre le bouton du panel (HTTP) et la commande de chat
function registerPlayerInternal(pseudo, isSub) {
  if (gamePhase() !== "lobby") return { ok: false, reason: "closed" };
  if (!state.players.some((p) => p.pseudo === pseudo)) {
    state.players.push({ pseudo, isSub: !!isSub });
  }
  return { ok: true };
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.send("🐟 Backend Carthon Plein en ligne !");
});

app.get("/privacy", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Politique de confidentialité - Carthon Plein</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #241C15; background:#FBF2D9; }
    h1 { color: #3C86AA; }
    h2 { margin-top: 30px; }
  </style>
</head>
<body>
  <h1>🐟 Politique de confidentialité - Carthon Plein</h1>
  <p><em>Dernière mise à jour : 2026</em></p>
  <h2>Ce que l'extension utilise</h2>
  <p>Carthon Plein est une extension Twitch de loto/bingo interactif. Pour fonctionner, elle utilise :</p>
  <ul>
    <li>Le pseudo Twitch que vous saisissez vous-même (dans le panneau) ou votre pseudo de chat (si vous vous inscrivez via la commande !carthon) — utilisé uniquement pour générer votre carton et l'afficher dans le classement de la partie en cours.</li>
    <li>Votre statut d'abonné à la chaîne (le cas échéant), pour vous attribuer un carton bonus.</li>
  </ul>
  <h2>Ce que l'extension NE fait PAS</h2>
  <ul>
    <li>Elle ne collecte aucune donnée personnelle au-delà du pseudo utilisé pour la partie.</li>
    <li>Elle ne partage aucune information avec des tiers.</li>
    <li>Elle ne stocke aucune donnée au-delà de la durée d'une partie (les données sont effacées à chaque nouvelle partie).</li>
    <li>Elle n'utilise aucun cookie de suivi.</li>
  </ul>
  <h2>Contact</h2>
  <p>Pour toute question : <a href="mailto:carthonplein@gmail.com">carthonplein@gmail.com</a></p>
</body>
</html>`);
});

app.get("/chat-overlay", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8" />
<title>Carthon Plein - Chat Overlay</title>
<script src="https://cdn.jsdelivr.net/npm/tmi.js@1.8.5/dist/tmi.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Baloo+2:wght@600;700&family=Inter:wght@400;500;600&display=swap');

  :root {
    --ink: #241C15;
    --cream: #F3E0B0;
    --cream-light: #FBF2D9;
    --ocean: #3C86AA;
    --gold: #D9A62B;
    --green: #4C8C5B;
    --red: #B5493A;
  }

  * { box-sizing: border-box; }

  html, body {
    margin: 0;
    padding: 0;
    background: transparent;
    overflow: hidden;
    font-family: 'Inter', sans-serif;
  }

  /* ---- CHANGE ICI la taille de la zone de chat ---- */
  #chat-container {
    width: 420px;
    height: 700px;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    padding: 12px;
    gap: 8px;
  }

  .msg {
    background: var(--cream-light);
    border: 3px solid var(--ink);
    border-radius: 14px;
    padding: 8px 12px;
    box-shadow: 0 3px 0 var(--ink);
    animation: slideIn 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
    word-wrap: break-word;
    max-width: 100%;
  }

  .msg.sub {
    background: linear-gradient(135deg, var(--cream-light), #FFF3D6);
    border-color: var(--gold);
  }

  .msg.mod {
    border-color: var(--green);
  }

  .msg.broadcaster {
    background: var(--ink);
    border-color: var(--gold);
  }
  .msg.broadcaster .username,
  .msg.broadcaster .text {
    color: var(--cream-light);
  }

  @keyframes slideIn {
    from { transform: translateY(16px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

  @keyframes fadeOut {
    from { opacity: 1; max-height: 200px; margin-bottom: 8px; }
    to { opacity: 0; max-height: 0; margin-bottom: 0; padding-top: 0; padding-bottom: 0; border-width: 0; }
  }

  .msg.leaving {
    animation: fadeOut 0.4s ease forwards;
    overflow: hidden;
  }

  .badges {
    display: inline-flex;
    gap: 3px;
    vertical-align: middle;
    margin-right: 4px;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border-radius: 4px;
    font-size: 10px;
  }
  .badge.badge-broadcaster { background: var(--gold); }
  .badge.badge-mod { background: var(--green); }
  .badge.badge-sub { background: var(--red); color: var(--cream-light); }

  .username {
    font-family: 'Baloo 2', sans-serif;
    font-weight: 700;
    font-size: 15px;
    color: var(--ocean);
  }

  .text {
    font-size: 14px;
    color: var(--ink);
    margin-top: 2px;
    line-height: 1.35;
  }

  .text img.emote {
    height: 22px;
    vertical-align: middle;
    margin: 0 1px;
  }
</style>
</head>
<body>
  <div id="chat-container"></div>

  <script>
    // ---- CONFIGURATION ----
    const CHANNEL = "carthonplein";           // ta chaîne Twitch
    const MAX_MESSAGES = 8;                    // nombre de messages visibles à la fois
    const MESSAGE_LIFETIME_MS = 25000;         // durée avant qu'un message disparaisse (ms)

    const container = document.getElementById("chat-container");

    function pickBadgeClass(tags) {
      if (tags.badges && tags.badges.broadcaster) return "broadcaster";
      if (tags.mod || (tags.badges && tags.badges.moderator)) return "mod";
      if (tags.subscriber || (tags.badges && tags.badges.subscriber)) return "sub";
      return "";
    }

    function renderBadges(tags) {
      let html = '<span class="badges">';
      if (tags.badges && tags.badges.broadcaster) {
        html += '<span class="badge badge-broadcaster">🐟</span>';
      }
      if (tags.mod || (tags.badges && tags.badges.moderator)) {
        html += '<span class="badge badge-mod">🛡️</span>';
      }
      if (tags.subscriber || (tags.badges && tags.badges.subscriber)) {
        html += '<span class="badge badge-sub">⭐</span>';
      }
      html += '</span>';
      return html;
    }

    // Remplace les emotes Twitch (positions données par tags.emotes) par des <img>
    function renderMessageWithEmotes(message, emotes) {
      if (!emotes || Object.keys(emotes).length === 0) {
        return escapeHtml(message);
      }
      // Construit la liste [{start, end, id}] triée
      const ranges = [];
      for (const id in emotes) {
        emotes[id].forEach((pos) => {
          const [start, end] = pos.split("-").map(Number);
          ranges.push({ start, end, id });
        });
      }
      ranges.sort((a, b) => a.start - b.start);

      let result = "";
      let cursor = 0;
      const chars = Array.from(message); // gère les emojis multi-octets correctement

      ranges.forEach((r) => {
        result += escapeHtml(chars.slice(cursor, r.start).join(""));
        const emoteUrl = "https://static-cdn.jtvnw.net/emoticons/v2/" + r.id + "/default/dark/2.0";
        result += '<img class="emote" src="' + emoteUrl + '" alt="" />';
        cursor = r.end + 1;
      });
      result += escapeHtml(chars.slice(cursor).join(""));
      return result;
    }

    function escapeHtml(str) {
      const div = document.createElement("div");
      div.textContent = str;
      return div.innerHTML;
    }

    function addMessage(tags, message) {
      const badgeClass = pickBadgeClass(tags);
      const displayName = tags["display-name"] || tags.username;
      const color = tags.color || "var(--ocean)";

      const el = document.createElement("div");
      el.className = "msg" + (badgeClass ? " " + badgeClass : "");
      el.innerHTML =
        '<div>' + renderBadges(tags) +
        '<span class="username" style="color:' + (badgeClass === "broadcaster" ? "" : color) + '">' + escapeHtml(displayName) + '</span>' +
        '</div>' +
        '<div class="text">' + renderMessageWithEmotes(message, tags.emotes) + '</div>';

      container.appendChild(el);

      // Limite le nombre de messages visibles
      while (container.children.length > MAX_MESSAGES) {
        container.removeChild(container.firstChild);
      }

      // Disparition automatique après un délai
      setTimeout(() => {
        if (!el.parentNode) return;
        el.classList.add("leaving");
        setTimeout(() => el.remove(), 450);
      }, MESSAGE_LIFETIME_MS);
    }

    const client = new tmi.Client({
      channels: [CHANNEL],
    });

    client.connect().catch(console.error);

    client.on("message", (channel, tags, message, self) => {
      addMessage(tags, message);
    });
  </script>
</body>
</html>
`);
});

app.get("/state", (req, res) => {
  const drawnSet = new Set(state.drawn);
  res.json({
    drawn: state.drawn,
    players: state.players.map((p) => ({ pseudo: p.pseudo, isSub: p.isSub })),
    gamePhase: gamePhase(),
    started: state.started,
    tierWinners: state.tierWinners,
    winner: state.winner,
    leaderboard: computeLeaderboard(drawnSet),
  });
});

app.post("/register", (req, res) => {
  const { pseudo, isSub } = req.body || {};
  if (!pseudo || typeof pseudo !== "string") {
    return res.status(400).json({ error: "pseudo manquant" });
  }
  const result = registerPlayerInternal(pseudo, isSub);
  if (!result.ok) {
    return res.status(403).json({ error: "inscriptions fermées pour cette partie" });
  }
  const grid = generateCard(pseudo);
  const bonusGrid = isSub ? generateCard(pseudo + "#sub") : null;
  res.json({ grid, bonusGrid });
});

app.get("/card/:pseudo", (req, res) => {
  const pseudo = req.params.pseudo;
  const player = state.players.find((p) => p.pseudo === pseudo);
  if (!player) {
    return res.json({ registered: false });
  }
  const grid = generateCard(pseudo);
  const bonusGrid = player.isSub ? generateCard(pseudo + "#sub") : null;
  res.json({ registered: true, grid, bonusGrid });
});

// ---------- Résolution d'identité (identifiant Twitch réel -> pseudo) ----------
const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID;
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;

let appAccessToken = null;
let appAccessTokenExpiry = 0;

async function getAppAccessToken() {
  if (appAccessToken && Date.now() < appAccessTokenExpiry - 60000) return appAccessToken;
  const res = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: TWITCH_CLIENT_ID,
      client_secret: TWITCH_CLIENT_SECRET,
      grant_type: "client_credentials",
    }),
  });
  const data = await res.json();
  appAccessToken = data.access_token;
  appAccessTokenExpiry = Date.now() + (data.expires_in || 0) * 1000;
  return appAccessToken;
}

app.get("/identify/:userId", async (req, res) => {
  const userId = req.params.userId;
  if (!/^\d+$/.test(userId)) {
    // Identifiant opaque (U- ou A-) : identité non partagée par le viewer
    return res.json({ linked: false });
  }
  try {
    const token = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?id=" + userId, {
      headers: {
        "Client-Id": TWITCH_CLIENT_ID,
        Authorization: "Bearer " + token,
      },
    });
    const data = await r.json();
    const user = data.data && data.data[0];
    if (!user) return res.json({ linked: false });
    res.json({ linked: true, pseudo: user.display_name });
  } catch (e) {
    res.status(500).json({ linked: false, error: "erreur API Twitch" });
  }
});

app.post("/draw", (req, res) => {
  if (!checkAdmin(req, res)) return;
  if (gamePhase() === "finished") return res.status(403).json({ error: "partie terminée" });
  const drawnSet = new Set(state.drawn);
  const remaining = [];
  for (let n = 1; n <= TOTAL_NUMBERS; n++) if (!drawnSet.has(n)) remaining.push(n);
  if (remaining.length === 0) return res.status(403).json({ error: "grille épuisée" });
  const n = remaining[Math.floor(Math.random() * remaining.length)];
  state.drawn.push(n);
  refreshTiersAndWinner();
  res.json({ drawn: n });
});

app.post("/reset", (req, res) => {
  if (!checkAdmin(req, res)) return;
  state = { drawn: [], players: [], tierWinners: { 1: null, 2: null, 3: null }, winner: null, started: true };
  res.json({ ok: true });
});

// ---------- Bot de chat : inscription via "!carthon" ----------
const BOT_USERNAME = process.env.BOT_USERNAME;
const BOT_OAUTH_TOKEN = process.env.BOT_OAUTH_TOKEN;
const CHANNEL_NAME = process.env.CHANNEL_NAME;

if (BOT_USERNAME && BOT_OAUTH_TOKEN && CHANNEL_NAME) {
  const client = new tmi.Client({
    identity: { username: BOT_USERNAME, password: BOT_OAUTH_TOKEN },
    channels: [CHANNEL_NAME],
  });

  client.connect().catch((err) => console.log("Erreur de connexion au chat :", err));

  client.on("connected", () => {
    console.log("Bot de chat connecté sur #" + CHANNEL_NAME);
  });

  client.on("message", (channel, tags, message, self) => {
    if (self) return;
    const text = message.trim().toLowerCase();
    if (text === "!carthon") {
      const pseudo = tags["display-name"] || tags.username;
      const isSub = !!tags.subscriber;
      const result = registerPlayerInternal(pseudo, isSub);
      if (result.ok) {
        client.say(channel, "@" + pseudo + " tu es inscrit(e) au Carthon Plein 🐟 va voir ton carton dans le panneau de l'extension !");
      } else {
        client.say(channel, "@" + pseudo + " les inscriptions sont fermées pour cette partie, à la prochaine !");
      }
    }
  });
} else {
  console.log("Bot de chat non configuré (BOT_USERNAME / BOT_OAUTH_TOKEN / CHANNEL_NAME manquants) — l'inscription par bouton reste disponible.");
}

app.listen(PORT, () => {
  console.log("Serveur démarré sur le port " + PORT);
});
