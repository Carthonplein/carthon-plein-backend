bash

cat /home/claude/carthon-plein-backend/server.js
Sortie

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

app.get("/state", (req, res) => {
  const drawnSet = new Set(state.drawn);
  res.json({
    drawn: state.drawn,
    players: state.players.map((p) => ({ pseudo: p.pseudo, isSub: p.isSub })),
    gamePhase: gamePhase(),
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
  const isSub = player ? player.isSub : false;
  const grid = generateCard(pseudo);
  const bonusGrid = isSub ? generateCard(pseudo + "#sub") : null;
  res.json({ grid, bonusGrid });
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
  state = { drawn: [], players: [], tierWinners: { 1: null, 2: null, 3: null }, winner: null };
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
