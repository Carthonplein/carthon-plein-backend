const express = require("express");
const cors = require("cors");

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
// Attention : cet état est remis à zéro si le serveur redémarre
// (ex: après une longue période d'inactivité sur l'offre gratuite Render).
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

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.send("🐟 Backend Carthon Plein en ligne !");
});

// État complet de la partie (numéros tirés, joueurs, paliers, classement, gagnant)
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

// Un viewer s'inscrit et récupère son carton
app.post("/register", (req, res) => {
  const { pseudo, isSub } = req.body || {};
  if (!pseudo || typeof pseudo !== "string") {
    return res.status(400).json({ error: "pseudo manquant" });
  }
  if (gamePhase() !== "lobby") {
    return res.status(403).json({ error: "inscriptions fermées pour cette partie" });
  }
  if (!state.players.some((p) => p.pseudo === pseudo)) {
    state.players.push({ pseudo, isSub: !!isSub });
  }
  const grid = generateCard(pseudo);
  const bonusGrid = isSub ? generateCard(pseudo + "#sub") : null;
  res.json({ grid, bonusGrid });
});

// Récupérer le carton d'un viewer déjà inscrit (pour réafficher sans re-générer)
app.get("/card/:pseudo", (req, res) => {
  const pseudo = req.params.pseudo;
  const player = state.players.find((p) => p.pseudo === pseudo);
  const isSub = player ? player.isSub : false;
  const grid = generateCard(pseudo);
  const bonusGrid = isSub ? generateCard(pseudo + "#sub") : null;
  res.json({ grid, bonusGrid });
});

// Le streamer tire un numéro (protégé par la clé admin)
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

// Le streamer relance une nouvelle partie (protégé par la clé admin)
app.post("/reset", (req, res) => {
  if (!checkAdmin(req, res)) return;
  state = { drawn: [], players: [], tierWinners: { 1: null, 2: null, 3: null }, winner: null };
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Serveur démarré sur le port " + PORT);
});
