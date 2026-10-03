const express = require("express");
const cors = require("cors");
const tmi = require("tmi.js");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Secret de l'extension Twitch (console développeur Twitch → ton extension →
// onglet "Secret", format base64). Sert à vérifier que le token envoyé par
// le client vient bien de Twitch et n'a pas été fabriqué par un viewer —
// remplace l'ancienne clé admin partagée, qui était visible en clair dans le
// JS envoyé à tout le monde (n'importe qui pouvait la copier et se faire
// passer pour le streamer directement auprès du serveur).
const TWITCH_EXT_SECRET = process.env.TWITCH_EXT_SECRET;

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

// Vérifie la signature (HMAC-SHA256) et l'expiration d'un token JWT signé
// par Twitch pour cette extension, et renvoie son payload décodé si valide,
// sinon null. Pas de librairie externe nécessaire : le format des tokens
// d'extension Twitch est un HS256 classique, une simple vérification HMAC
// suffit et évite une dépendance npm supplémentaire à faire déployer.
function verifyTwitchExtensionToken(token) {
  if (!token || typeof token !== "string" || !TWITCH_EXT_SECRET) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;
  try {
    const secretKey = Buffer.from(TWITCH_EXT_SECRET, "base64");
    const expectedSig = crypto.createHmac("sha256", secretKey).update(headerB64 + "." + payloadB64).digest();
    const actualSig = base64UrlDecode(signatureB64);
    if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) {
      return null; // signature invalide : token forgé ou modifié
    }
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString("utf8"));
    if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp) return null; // expiré
    return payload;
  } catch (e) {
    return null;
  }
}

// ---------- Stockage persistant (Upstash Redis) ----------
// Sert uniquement à ce qui ne doit JAMAIS être perdu (cadres/badges/titres
// possédés par les viewers) — indépendant de Render, survit à tous les
// redéploiements/redémarrages du serveur, contrairement au reste de `state`.
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const REDIS_ENABLED = !!(REDIS_URL && REDIS_TOKEN);

async function redisGetJSON(key, fallback) {
  if (!REDIS_ENABLED) return fallback;
  try {
    const res = await fetch(REDIS_URL + "/get/" + encodeURIComponent(key), {
      headers: { Authorization: "Bearer " + REDIS_TOKEN },
    });
    const data = await res.json();
    return data.result ? JSON.parse(data.result) : fallback;
  } catch (e) {
    console.error("Erreur lecture Redis (" + key + ") :", e.message);
    return fallback;
  }
}

async function redisSetJSON(key, value) {
  if (!REDIS_ENABLED) return;
  try {
    await fetch(REDIS_URL + "/set/" + encodeURIComponent(key), {
      method: "POST",
      headers: { Authorization: "Bearer " + REDIS_TOKEN },
      body: JSON.stringify(value),
    });
  } catch (e) {
    console.error("Erreur écriture Redis (" + key + ") :", e.message);
  }
}

const GRID_SIZE = 4;
const TOTAL_NUMBERS = 75;
const SUPER_THRESHOLD = 45; // Carthon Plein réussi en 45 tirages ou moins = "Super Carthon Plein"
const SUPER_FRAME_KEY = "super"; // cadre exclusif, jamais obtenu autrement

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
function newGameId() {
  // identifiant unique par partie, mélangé au pseudo pour générer un carton
  // différent à chaque partie tout en restant stable pendant une même partie
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// Nombre minimum de cases manquantes pour compléter une colonne (la plus proche)
function closestColumnRemaining(grid, drawnSet) {
  let best = GRID_SIZE;
  for (let c = 0; c < GRID_SIZE; c++) {
    let missing = 0;
    for (let r = 0; r < GRID_SIZE; r++) {
      if (!drawnSet.has(grid[r][c])) missing++;
    }
    if (missing < best) best = missing;
  }
  return best;
}

let state = {
  drawn: [],
  players: [], // { pseudo, isSub }
  tierWinners: { 1: null, 2: null, 3: null },
  winner: null, // { pseudo, cardType }
  pendingFinalists: [], // ex-æquo pour le Carthon Plein, en attente d'un tirage à la roue
  pendingFinalistsDrawCount: null, // nombre de tirages au moment de l'égalité, pour savoir si ce sera un Super Carthon Plein
  wheelSpin: null, // { id, names, winnerIndex, ts } — animation de roue partagée avec tous les viewers
  started: false, // devient true dès le premier clic sur "Nouvelle partie" (rend l'overlay visible aux viewers)
  gameId: newGameId(),
  ballDrops: [], // { id, pseudo, number, ts } — effet visuel "!numero", purgé après quelques secondes
  duckEvent: null, // { id, ts } — easter egg "canard volant", déclenché manuellement par le streamer
  panDrops: [], // { id, ts } — easter egg "!pan" (explosion à un endroit/taille aléatoire), purgé après quelques secondes
};

// Anti-spam pour "!pan" : un seul déclenchement autorisé toutes les
// PAN_COOLDOWN_MS, tous chatteurs confondus, pour éviter qu'un raid de
// "!pan" ne recouvre l'écran d'explosions. Volontairement en dehors de
// `state` (pas remis à zéro par "Nouvelle partie").
let lastPanTriggerTs = 0;
const PAN_COOLDOWN_MS = 1500;

// Cadres débloqués par pseudo (dons, etc.) — volontairement EN DEHORS de
// `state` pour ne jamais être effacés par "Nouvelle partie" : { pseudo: ["nature", ...] }
// Chargé depuis Redis au démarrage, chaque écriture est aussi renvoyée là-bas.
let unlockedFramesByPseudo = {};

function grantFrame(pseudo, frameKey) {
  if (!unlockedFramesByPseudo[pseudo]) unlockedFramesByPseudo[pseudo] = [];
  if (!unlockedFramesByPseudo[pseudo].includes(frameKey)) {
    unlockedFramesByPseudo[pseudo].push(frameKey);
    redisSetJSON("unlockedFramesByPseudo", unlockedFramesByPseudo);
  }
}

// Retire un cadre déjà débloqué (ex: erreur du streamer en distribuant le
// mauvais cadre). Si le viewer l'avait équipé, on le repasse sur "Aucun
// cadre" pour ne pas laisser un badge/cadre fantôme affiché.
function revokeFrame(pseudo, frameKey) {
  if (unlockedFramesByPseudo[pseudo]) {
    const idx = unlockedFramesByPseudo[pseudo].indexOf(frameKey);
    if (idx !== -1) {
      unlockedFramesByPseudo[pseudo].splice(idx, 1);
      redisSetJSON("unlockedFramesByPseudo", unlockedFramesByPseudo);
    }
  }
  if (displayChoiceByPseudo[pseudo] && displayChoiceByPseudo[pseudo].frame === frameKey) {
    displayChoiceByPseudo[pseudo].frame = "none";
    redisSetJSON("displayChoiceByPseudo", displayChoiceByPseudo);
  }
}

// Cadres qu'on peut acheter (par don) — à étendre au fil de futurs cadres.
// Le cadre "super" n'y figure pas exprès : il se mérite, il ne s'achète pas.
// Ordre = priorité par défaut du badge (le premier possédé dans cet ordre
// gagne, tant que le viewer n'a rien choisi lui-même).
const PURCHASABLE_FRAMES = ["signature", "noel", "valentine", "easter", "pirate", "space", "formula1", "halloween", "nature"];

// Choix d'affichage de chaque viewer (badge/titre qu'il a sélectionné parmi
// ceux disponibles) — comme unlockedFramesByPseudo, chargé/sauvé sur Redis.
let displayChoiceByPseudo = {};

// Nombre de victoires par pseudo — { pseudo: { total: N, super: M } } —
// persisté sur Redis comme le reste, pour les titres basés sur les gains.
let winsByPseudo = {};

// Dernier pseudo connu pour chaque identifiant Twitch STABLE (tags["user-id"]
// des messages de chat) — { twitchUserId: "pseudo" }. Contrairement au
// pseudo, cet ID ne change jamais, même si le viewer renomme son compte
// Twitch. Permet de détecter un renommage et de migrer automatiquement les
// cadres/victoires/préférences vers le nouveau pseudo au lieu de les perdre.
// Ne concerne que l'inscription via le bot de chat ("!carthon"), seule voie
// qui fournit cet ID ; l'inscription manuelle depuis le panneau ne le fait
// pas (le viewer y tape un pseudo à la main, sans lien avec son compte).
let pseudoByUserId = {};

function reconcilePseudoRename(userId, newPseudo) {
  if (!userId || !newPseudo) return;
  const oldPseudo = pseudoByUserId[userId];
  if (oldPseudo && oldPseudo !== newPseudo) {
    // Renommage détecté : on rapatrie les données de l'ancien pseudo sur le
    // nouveau (fusion si le nouveau pseudo avait déjà quelque chose, ce qui
    // peut arriver si quelqu'un d'autre a entre-temps pris cet ancien pseudo).
    if (unlockedFramesByPseudo[oldPseudo]) {
      const merged = Array.from(
        new Set([...(unlockedFramesByPseudo[newPseudo] || []), ...unlockedFramesByPseudo[oldPseudo]])
      );
      unlockedFramesByPseudo[newPseudo] = merged;
      delete unlockedFramesByPseudo[oldPseudo];
      redisSetJSON("unlockedFramesByPseudo", unlockedFramesByPseudo);
    }
    if (winsByPseudo[oldPseudo]) {
      const prevNew = winsByPseudo[newPseudo] || { total: 0, super: 0 };
      const prevOld = winsByPseudo[oldPseudo];
      winsByPseudo[newPseudo] = { total: prevNew.total + prevOld.total, super: prevNew.super + prevOld.super };
      delete winsByPseudo[oldPseudo];
      redisSetJSON("winsByPseudo", winsByPseudo);
    }
    if (displayChoiceByPseudo[oldPseudo] && !displayChoiceByPseudo[newPseudo]) {
      displayChoiceByPseudo[newPseudo] = displayChoiceByPseudo[oldPseudo];
      delete displayChoiceByPseudo[oldPseudo];
      redisSetJSON("displayChoiceByPseudo", displayChoiceByPseudo);
    }
  }
  if (pseudoByUserId[userId] !== newPseudo) {
    pseudoByUserId[userId] = newPseudo;
    redisSetJSON("pseudoByUserId", pseudoByUserId);
  }
}

// Contrôlé UNIQUEMENT par le streamer/modérateur (bouton admin), mais
// s'applique à TOUS les viewers : masque entièrement l'overlay pour eux.
// Volontairement en dehors de `state` pour survivre à "Nouvelle partie",
// et persisté sur Redis pour survivre aussi à un redémarrage du serveur.
let overlayVisible = true;

function recordWin(pseudo, isSuper) {
  if (!winsByPseudo[pseudo]) winsByPseudo[pseudo] = { total: 0, super: 0 };
  winsByPseudo[pseudo].total += 1;
  if (isSuper) winsByPseudo[pseudo].super += 1;
  redisSetJSON("winsByPseudo", winsByPseudo);
}

// Calcule tout ce qu'un pseudo a le droit d'afficher : la liste des badges
// et titres disponibles (selon ses cadres possédés), pour construire le
// sélecteur côté viewer.
function getAvailableStatuses(pseudo) {
  const isBroadcaster = CHANNEL_NAME && pseudo && pseudo.toLowerCase() === CHANNEL_NAME.toLowerCase();
  const frames = isBroadcaster ? [...PURCHASABLE_FRAMES, SUPER_FRAME_KEY] : (unlockedFramesByPseudo[pseudo] || []);
  const hasSuper = isBroadcaster || frames.includes(SUPER_FRAME_KEY);
  const wins = isBroadcaster ? { total: 3, super: 2 } : (winsByPseudo[pseudo] || { total: 0, super: 0 });

  const availableBadges = [];
  if (hasSuper) availableBadges.push("super");
  PURCHASABLE_FRAMES.forEach((key) => {
    if (isBroadcaster || frames.includes(key)) availableBadges.push(key);
  });

  const ownedPurchasable = isBroadcaster ? PURCHASABLE_FRAMES : PURCHASABLE_FRAMES.filter((f) => frames.includes(f));

  // Du plus prestigieux au moins prestigieux — l'ordre définit aussi le
  // choix par défaut (le premier de la liste) tant que le viewer n'a rien
  // choisi lui-même dans son sélecteur.
  const availableTitles = [];
  if (wins.super >= 2) availableTitles.push("mythique");
  if (hasSuper) availableTitles.push("legend");
  if (wins.total >= 3) availableTitles.push("multi_champion");
  if (PURCHASABLE_FRAMES.length > 0 && ownedPurchasable.length === PURCHASABLE_FRAMES.length) availableTitles.push("grand_collector");
  if (wins.total >= 1) availableTitles.push("chanceux");
  if (isBroadcaster || frames.length >= 2) availableTitles.push("collector");

  return { availableBadges, availableTitles };
}

// Calcule le badge + titre RÉELLEMENT affichés publiquement pour un pseudo
// (classement, paliers, gagnant, boules "!numero"...). Le badge suit
// automatiquement le cadre équipé par le viewer (pas de choix séparé) ; le
// titre reste un choix indépendant parmi ceux disponibles.
function getPublicStatus(pseudo) {
  const { availableBadges, availableTitles } = getAvailableStatuses(pseudo);
  const choice = displayChoiceByPseudo[pseudo] || {};

  let badge = null;
  if (choice.frame && (choice.frame === "none" || availableBadges.includes(choice.frame))) {
    badge = choice.frame === "none" ? null : choice.frame;
  } else {
    badge = availableBadges[0] || null; // tant que rien n'a encore été équipé, priorité par défaut
  }

  let title = null;
  if (choice.title && (choice.title === "none" || availableTitles.includes(choice.title))) {
    title = choice.title === "none" ? null : choice.title;
  } else {
    title = availableTitles[0] || null;
  }

  return { badge, title };
}

function gamePhase() {
  if (state.winner) return "finished";
  if (state.pendingFinalists && state.pendingFinalists.length > 0) return "finished";
  if (state.drawn.length > 0) return "playing";
  return "lobby";
}

function computeEntrants() {
  const entrants = [];
  for (const p of state.players) {
    entrants.push({ pseudo: p.pseudo, cardType: "principal", grid: generateCard(p.pseudo + "#" + state.gameId) });
    if (p.isSub) entrants.push({ pseudo: p.pseudo, cardType: "bonus", grid: generateCard(p.pseudo + "#sub#" + state.gameId) });
  }
  return entrants;
}

// Classement complet (pas seulement le top 3) : un seul carton par pseudo
// (le meilleur des deux si abonné), trié par proximité du Carthon Plein.
function computeFullStandings(drawnSet) {
  const bestByPseudo = new Map();
  for (const p of state.players) {
    const cards = [{ cardType: "principal", grid: generateCard(p.pseudo + "#" + state.gameId) }];
    if (p.isSub) cards.push({ cardType: "bonus", grid: generateCard(p.pseudo + "#sub#" + state.gameId) });
    for (const c of cards) {
      const status = columnStatus(c.grid, drawnSet);
      const marked = c.grid.flat().filter((v) => drawnSet.has(v)).length;
      const remaining = GRID_SIZE * GRID_SIZE - marked;
      const current = bestByPseudo.get(p.pseudo);
      const better =
        !current || remaining < current.remaining || (remaining === current.remaining && status.count > current.count);
      if (better) bestByPseudo.set(p.pseudo, { pseudo: p.pseudo, cardType: c.cardType, count: status.count, remaining });
    }
  }
  return [...bestByPseudo.values()].sort((a, b) => a.remaining - b.remaining || b.count - a.count);
}

function computeLeaderboard(drawnSet) {
  return computeFullStandings(drawnSet)
    .slice(0, 3)
    .map((e) => ({ ...e, ...getPublicStatus(e.pseudo) }));
}

// Position (1-based) et numéros restants d'un pseudo précis dans le
// classement complet — utilisé pour lui afficher son propre rang quand il
// n'est pas dans le top 3 visible par tous.
function getStandingFor(pseudo, drawnSet) {
  const standings = computeFullStandings(drawnSet);
  const idx = standings.findIndex((e) => e.pseudo === pseudo);
  if (idx === -1) return null;
  return { rank: idx + 1, total: standings.length, remaining: standings[idx].remaining, count: standings[idx].count };
}

// Regroupe une liste de cartons par pseudo : une même personne gagnant /
// atteignant un palier avec son carton principal ET son carton bonus en
// même temps ne doit jamais compter comme une égalité "contre elle-même" —
// un seul candidat par pseudo, en privilégiant le carton principal comme
// représentant.
function dedupeByPseudo(list) {
  const byPseudo = new Map();
  list.forEach((f) => {
    const existing = byPseudo.get(f.pseudo);
    if (!existing || (existing.cardType === "bonus" && f.cardType === "principal")) {
      byPseudo.set(f.pseudo, f);
    }
  });
  return [...byPseudo.values()];
}

function refreshTiersAndWinner() {
  if (state.winner) return;
  if (state.pendingFinalists && state.pendingFinalists.length > 0) return; // en attente du tirage à la roue
  const drawnSet = new Set(state.drawn);
  const entrants = computeEntrants();
  for (let level = 1; level <= GRID_SIZE - 1; level++) {
    if (state.tierWinners[level]) continue;
    // capture TOUS les joueurs qui atteignent ce palier au même tirage (ex-æquo),
    // en excluant les "égalités" entre le carton principal et le carton bonus
    // d'une seule et même personne.
    const found = dedupeByPseudo(entrants.filter((e) => columnStatus(e.grid, drawnSet).count >= level));
    if (found.length > 0) {
      state.tierWinners[level] = found.map((e) => ({ pseudo: e.pseudo, cardType: e.cardType, ...getPublicStatus(e.pseudo) }));
    }
  }
  const finalists = entrants.filter((e) => columnStatus(e.grid, drawnSet).blackout);
  if (finalists.length > 0) {
    const uniqueFinalists = dedupeByPseudo(finalists);

    if (uniqueFinalists.length === 1) {
      const isSuper = state.drawn.length <= SUPER_THRESHOLD;
      if (isSuper) grantFrame(uniqueFinalists[0].pseudo, SUPER_FRAME_KEY);
      recordWin(uniqueFinalists[0].pseudo, isSuper);
      state.winner = { pseudo: uniqueFinalists[0].pseudo, cardType: uniqueFinalists[0].cardType, isSuper, ...getPublicStatus(uniqueFinalists[0].pseudo) };
    } else {
      // vraie égalité entre personnes différentes : le streamer départagera à la roue
      state.pendingFinalists = uniqueFinalists.map((e) => ({ pseudo: e.pseudo, cardType: e.cardType }));
      state.pendingFinalistsDrawCount = state.drawn.length; // conservé pour savoir si ce sera un Super Carthon Plein une fois le tirage résolu
    }
  }
}

// Vérifie que la requête vient bien du streamer ou d'un modérateur, via le
// token Twitch signé envoyé en en-tête "Authorization: Bearer <token>" —
// et non plus via une clé partagée envoyée dans le corps de la requête.
function checkAdmin(req, res) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const payload = verifyTwitchExtensionToken(token);
  const role = payload && payload.role;
  if (role !== "broadcaster" && role !== "moderator") {
    res.status(401).json({ error: "accès streamer ou modérateur requis" });
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
    <li>Votre pseudo Twitch, obtenu via l'autorisation d'identité Twitch lorsque vous vous inscrivez avec le bouton "S'inscrire", ou votre pseudo de chat si vous vous inscrivez via la commande "!carthon" — utilisé uniquement pour générer votre carton et l'afficher dans le classement de la partie en cours.</li>
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

app.get("/reglement", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Règlement du jeu - Carthon Plein</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; line-height: 1.65; color: #241C15; background:#FBF2D9; }
    h1 { color: #3C86AA; }
    h2 { margin-top: 28px; color: #241C15; border-bottom: 2px solid #D9A62B; padding-bottom: 4px; }
    p, li { font-size: 15px; }
  </style>
</head>
<body>
  <h1>🐟 Règlement du jeu "Carthon Plein"</h1>
  <p><em>Dernière mise à jour : 2026</em></p>

  <h2>Article 1 — Organisateur</h2>
  <p>Le jeu "Carthon Plein" est organisé par la chaîne Twitch Carthon Plein, sur la plateforme Twitch, dans le cadre de ses diffusions en direct. Contact : carthonplein@gmail.com</p>

  <h2>Article 2 — Participation</h2>
  <p>La participation est entièrement gratuite et sans obligation d'achat. Aucun paiement, abonnement ou don n'est requis pour participer ni pour avoir une chance de gagner le lot principal. Le jeu est ouvert à toute personne disposant d'un compte Twitch, sous réserve du respect du présent règlement.</p>

  <h2>Article 3 — Modalités du jeu</h2>
  <p>Pour participer, le viewer clique sur le bouton "S'inscrire" dans le panneau de l'extension pendant qu'une partie est ouverte aux inscriptions (ce qui nécessite d'autoriser l'extension à connaître son pseudo Twitch), ou, alternativement, tape la commande "!carthon" dans le chat de la chaîne. Un carton personnel est alors généré. Le streamer tire ensuite des numéros parmi 1 et 75. Les joueurs abonnés à la chaîne reçoivent en plus un carton bonus, sans surcoût ni condition supplémentaire. La partie se termine lorsqu'un joueur complète l'intégralité de son carton ("Carthon Plein").</p>

  <h2>Article 4 — Détermination du/des gagnant(s)</h2>
  <p>Le gagnant est le premier joueur dont le carton (principal ou bonus) est entièrement complété. En cas de complétion simultanée par plusieurs joueurs différents, un tirage au sort transparent (roue visible en direct par tous les viewers) désigne le gagnant final. Si un même joueur complète simultanément son carton principal et son carton bonus, sans qu'aucun autre joueur ne soit également ex-æquo, il est déclaré gagnant directement, sans tirage au sort.</p>

  <h2>Article 5 — Lots</h2>
  <p>La nature des lots (goodies, cartes cadeaux, etc.) est annoncée par l'organisateur avant ou pendant chaque partie. Les lots ne sont ni échangeables, ni remboursables, ni convertibles en espèces. L'organisateur se réserve le droit de modifier la nature des lots proposés d'une partie à l'autre.</p>

  <h2>Article 6 — Participants mineurs</h2>
  <p>La participation au jeu lui-même est ouverte sans condition d'âge. En revanche, si un gagnant est mineur, la remise du lot est conditionnée à l'accord explicite d'un parent ou représentant légal, qui devra être en copie des échanges relatifs à l'envoi du lot.</p>

  <h2>Article 7 — Données personnelles</h2>
  <p>Les seules données collectées sont le pseudo Twitch (obtenu via l'autorisation d'identité Twitch lors de l'inscription par bouton, ou via le pseudo de chat en cas d'inscription par la commande "!carthon"), utilisé pour le déroulement du jeu, et, en cas de gain d'un lot physique, une adresse postale, demandée uniquement au gagnant et utilisée exclusivement pour l'envoi du lot. Cette adresse n'est conservée que le temps nécessaire à l'expédition, puis supprimée. Aucune donnée n'est partagée avec des tiers. Pour toute question relative à vos données : carthonplein@gmail.com</p>

  <h2>Article 8 — Responsabilité</h2>
  <p>Ce jeu est organisé par la chaîne Carthon Plein et n'est ni sponsorisé, ni géré, ni associé à Twitch Interactive, Inc. L'organisateur ne saurait être tenu responsable en cas de dysfonctionnement technique indépendant de sa volonté (panne, coupure internet, bug de l'extension) empêchant le bon déroulement d'une partie.</p>

  <h2>Article 9 — Modification du règlement</h2>
  <p>L'organisateur se réserve le droit de modifier, suspendre ou annuler le jeu à tout moment si les circonstances l'exigent, sans que sa responsabilité puisse être engagée de ce fait. Toute modification du présent règlement sera annoncée sur la chaîne.</p>

  <h2>Article 10 — Droit applicable</h2>
  <p>Le présent règlement est soumis au droit français. Toute contestation relative à son application devra être adressée à carthonplein@gmail.com avant toute autre démarche.</p>
</body>
</html>`);
});

app.get("/state", (req, res) => {
  const drawnSet = new Set(state.drawn);
  // ne garde que les chutes de boules récentes (10 dernières secondes)
  const now = Date.now();
  state.ballDrops = state.ballDrops.filter((b) => now - b.ts < 10000);
  state.panDrops = state.panDrops.filter((p) => now - p.ts < 10000);
  res.json({
    drawn: state.drawn,
    players: state.players.map((p) => ({ pseudo: p.pseudo, isSub: p.isSub })),
    gamePhase: gamePhase(),
    started: state.started,
    tierWinners: state.tierWinners,
    winner: state.winner,
    pendingFinalists: state.pendingFinalists,
    wheelSpin: state.wheelSpin,
    leaderboard: computeLeaderboard(drawnSet),
    ballDrops: state.ballDrops,
    gameId: state.gameId,
    overlayVisible,
    duckEvent: state.duckEvent,
    panDrops: state.panDrops,
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
  const grid = generateCard(pseudo + "#" + state.gameId);
  const bonusGrid = isSub ? generateCard(pseudo + "#sub#" + state.gameId) : null;
  res.json({ grid, bonusGrid });
});

app.get("/card/:pseudo", (req, res) => {
  const pseudo = req.params.pseudo;
  const player = state.players.find((p) => p.pseudo === pseudo);
  const unlockedFrames = unlockedFramesByPseudo[pseudo] || [];
  const { availableBadges, availableTitles } = getAvailableStatuses(pseudo);
  const displayChoice = displayChoiceByPseudo[pseudo] || {};
  if (!player) {
    return res.json({ registered: false, unlockedFrames, availableBadges, availableTitles, displayChoice });
  }
  const grid = generateCard(pseudo + "#" + state.gameId);
  const bonusGrid = player.isSub ? generateCard(pseudo + "#sub#" + state.gameId) : null;
  const drawnSet = new Set(state.drawn);
  const myStanding = getStandingFor(pseudo, drawnSet);
  res.json({ registered: true, grid, bonusGrid, unlockedFrames, availableBadges, availableTitles, displayChoice, myStanding });
});

app.post("/set-display-choice", (req, res) => {
  const { pseudo, frame, title } = req.body || {};
  if (!pseudo || typeof pseudo !== "string") {
    return res.status(400).json({ error: "pseudo manquant" });
  }
  const { availableBadges, availableTitles } = getAvailableStatuses(pseudo);
  // Le badge n'est plus choisi séparément : il suit automatiquement le
  // cadre équipé, donc on valide "frame" contre les mêmes clés que les badges.
  if (frame !== undefined && frame !== "none" && frame !== null && !availableBadges.includes(frame)) {
    return res.status(400).json({ error: "cadre non disponible pour ce pseudo" });
  }
  if (title !== undefined && title !== "none" && title !== null && !availableTitles.includes(title)) {
    return res.status(400).json({ error: "titre non disponible pour ce pseudo" });
  }
  if (!displayChoiceByPseudo[pseudo]) displayChoiceByPseudo[pseudo] = {};
  if (frame !== undefined) displayChoiceByPseudo[pseudo].frame = frame || "none";
  if (title !== undefined) displayChoiceByPseudo[pseudo].title = title || "none";
  redisSetJSON("displayChoiceByPseudo", displayChoiceByPseudo);
  res.json({ ok: true, displayChoice: displayChoiceByPseudo[pseudo] });
});

app.post("/toggle-overlay", (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { visible } = req.body || {};
  overlayVisible = typeof visible === "boolean" ? visible : !overlayVisible;
  redisSetJSON("overlayVisible", overlayVisible);
  res.json({ ok: true, overlayVisible });
});

// Cadres jamais distribuables à la main (uniquement gagnés automatiquement,
// ex: Super Carthon Plein) — miroir de "exclusive: true" côté overlay.js.
const EXCLUSIVE_FRAMES = ["super"];

app.post("/grant-frame", (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { pseudo, frameKey } = req.body || {};
  if (!pseudo || typeof pseudo !== "string" || !frameKey || typeof frameKey !== "string") {
    return res.status(400).json({ error: "pseudo et frameKey requis" });
  }
  if (EXCLUSIVE_FRAMES.includes(frameKey)) {
    return res.status(400).json({ error: "ce cadre ne peut pas être distribué manuellement, il ne s'obtient qu'en le gagnant" });
  }
  grantFrame(pseudo, frameKey);
  res.json({ ok: true, pseudo, unlockedFrames: unlockedFramesByPseudo[pseudo] });
});

app.post("/revoke-frame", (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { pseudo, frameKey } = req.body || {};
  if (!pseudo || typeof pseudo !== "string" || !frameKey || typeof frameKey !== "string") {
    return res.status(400).json({ error: "pseudo et frameKey requis" });
  }
  revokeFrame(pseudo, frameKey);
  res.json({ ok: true, pseudo, unlockedFrames: unlockedFramesByPseudo[pseudo] || [] });
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

// ---------- OAuth broadcaster (nécessaire pour vérifier les abonnements) ----------
// Un token "app access token" (client_credentials, utilisé ci-dessus pour
// /identify) ne suffit PAS pour lire les abonnements d'une chaîne : Twitch
// exige un token appartenant au broadcaster lui-même, avec le scope
// "channel:read:subscriptions", obtenu une seule fois via une autorisation
// OAuth classique (voir /auth/twitch/start, à visiter une fois par le
// streamer). Le refresh_token est ensuite utilisé indéfiniment pour
// renouveler l'access_token automatiquement, sans jamais redemander.
const TWITCH_REDIRECT_URI = process.env.TWITCH_REDIRECT_URI || "https://carthon-plein-backend.onrender.com/auth/twitch/callback";

let broadcasterTokens = null; // { access_token, refresh_token, expires_at }
let broadcasterUserId = null; // résolu une fois via CHANNEL_NAME, mis en cache

app.get("/auth/twitch/start", (req, res) => {
  const url = "https://id.twitch.tv/oauth2/authorize?" + new URLSearchParams({
    client_id: TWITCH_CLIENT_ID,
    redirect_uri: TWITCH_REDIRECT_URI,
    response_type: "code",
    scope: "channel:read:subscriptions",
  });
  res.redirect(url);
});

app.get("/auth/twitch/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Code d'autorisation manquant.");
  try {
    const r = await fetch("https://id.twitch.tv/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: TWITCH_REDIRECT_URI,
      }),
    });
    const data = await r.json();
    if (!data.access_token) {
      return res.status(500).send("Échec de l'autorisation Twitch : " + JSON.stringify(data));
    }
    broadcasterTokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in || 0) * 1000,
    };
    await redisSetJSON("broadcasterTokens", broadcasterTokens);
    res.send("✅ Autorisation réussie ! Carthon Plein peut maintenant vérifier les abonnements automatiquement. Tu peux fermer cette page.");
  } catch (e) {
    res.status(500).send("Erreur : " + e.message);
  }
});

async function getBroadcasterAccessToken() {
  if (!broadcasterTokens) broadcasterTokens = await redisGetJSON("broadcasterTokens", null);
  if (!broadcasterTokens) return null; // pas encore autorisé (voir /auth/twitch/start)
  if (Date.now() < broadcasterTokens.expires_at - 60000) return broadcasterTokens.access_token;
  try {
    const r = await fetch("https://id.twitch.tv/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: broadcasterTokens.refresh_token,
      }),
    });
    const data = await r.json();
    if (!data.access_token) return null;
    broadcasterTokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || broadcasterTokens.refresh_token,
      expires_at: Date.now() + (data.expires_in || 0) * 1000,
    };
    await redisSetJSON("broadcasterTokens", broadcasterTokens);
    return broadcasterTokens.access_token;
  } catch (e) {
    console.error("Erreur rafraîchissement token broadcaster :", e.message);
    return null;
  }
}

async function getBroadcasterUserId() {
  if (broadcasterUserId) return broadcasterUserId;
  try {
    const token = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?login=" + encodeURIComponent(CHANNEL_NAME || ""), {
      headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + token },
    });
    const data = await r.json();
    const user = data.data && data.data[0];
    if (user) broadcasterUserId = user.id;
    return broadcasterUserId;
  } catch (e) {
    console.error("Erreur résolution ID broadcaster :", e.message);
    return null;
  }
}

// Vérifie si userId est abonné à la chaîne. Ne renvoie JAMAIS d'erreur qui
// bloquerait l'inscription : en cas de problème (token pas encore autorisé,
// API indisponible...), on renvoie simplement false — un abonné mal détecté
// perd son carton bonus pour cette inscription, mais peut toujours participer,
// et ce n'est jamais bloquant pour lui.
async function checkIsSubscriber(userId) {
  try {
    const token = await getBroadcasterAccessToken();
    const bId = await getBroadcasterUserId();
    if (!token || !bId) return false;
    const r = await fetch(
      "https://api.twitch.tv/helix/subscriptions?broadcaster_id=" + bId + "&user_id=" + userId,
      { headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + token } }
    );
    if (!r.ok) return false;
    const data = await r.json();
    return !!(data.data && data.data.length > 0);
  } catch (e) {
    console.error("Erreur vérification abonnement :", e.message);
    return false;
  }
}

// ---------- Inscription par bouton (liaison d'identité Twitch) ----------
// Remplace le besoin de taper "!carthon" dans le chat : le viewer clique sur
// un bouton dans l'overlay, autorise (une fois) le partage de son identité,
// et cet endpoint fait tout le reste automatiquement à partir de son vrai
// identifiant Twitch (jamais un pseudo fourni par le client, toujours vérifié
// via le token signé par Twitch — donc impossible à falsifier).
app.post("/register-by-identity", async (req, res) => {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const payload = verifyTwitchExtensionToken(token);
  if (!payload) return res.status(401).json({ error: "token invalide" });
  const userId = payload.user_id;
  if (!userId) return res.status(400).json({ error: "identité non partagée" });

  try {
    const appToken = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?id=" + userId, {
      headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + appToken },
    });
    const data = await r.json();
    const user = data.data && data.data[0];
    if (!user) return res.status(500).json({ error: "pseudo introuvable" });
    const pseudo = user.display_name;

    reconcilePseudoRename(userId, pseudo);
    const isSub = await checkIsSubscriber(userId);
    const result = registerPlayerInternal(pseudo, isSub);
    if (!result.ok) return res.status(403).json({ error: "inscriptions fermées pour cette partie" });

    const grid = generateCard(pseudo + "#" + state.gameId);
    const bonusGrid = isSub ? generateCard(pseudo + "#sub#" + state.gameId) : null;
    res.json({ ok: true, pseudo, isSub, grid, bonusGrid });
  } catch (e) {
    res.status(500).json({ error: "erreur serveur" });
  }
});

// ---------- Anti-spam des boules ----------
// Règles appliquées côté serveur (donc impossibles à contourner depuis le
// navigateur) :
//  - un joueur ne peut lâcher qu'UNE boule toutes les BALL_COOLDOWN_MS ;
//  - un même numéro ne peut être lâché qu'UNE fois par joueur et par partie ;
//  - au plus MAX_BALLS_ON_SCREEN boules à l'écran en même temps (garde-fou
//    contre un afflux de comptes qui cliqueraient tous en même temps).
// Le suivi est lié à l'identifiant de la partie : "Nouvelle partie" remet
// tout à zéro automatiquement.
const BALL_COOLDOWN_MS = 8000;
const MAX_BALLS_ON_SCREEN = 15;
const BALL_VISIBLE_MS = 10000; // même durée que la purge dans /state
let ballLog = { gameId: null, byPseudo: {} }; // byPseudo[pseudo] = { last, numbers: [] }

// ---------- Boule ("numéro proche") par double-clic (remplace "!23") ----------
// Même logique d'éligibilité que l'ancienne commande de chat (numéro sur le
// carton, pas encore tiré, et il reste 3 numéros ou moins sur l'ensemble du
// carton) — sauf que l'identité vient du token signé, jamais du client.
app.post("/drop-ball", (req, res) => {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const payload = verifyTwitchExtensionToken(token);
  if (!payload) return res.status(401).json({ error: "token invalide" });
  const userId = payload.user_id;
  if (!userId) return res.status(400).json({ error: "identité non partagée" });

  const pseudo = pseudoByUserId[userId];
  if (!pseudo) return res.status(403).json({ error: "non inscrit" });
  const player = state.players.find((p) => p.pseudo === pseudo);
  if (!player) return res.status(403).json({ error: "non inscrit" });

  const n = parseInt(req.body && req.body.number, 10);
  if (!n || n < 1 || n > TOTAL_NUMBERS) return res.status(400).json({ error: "numéro invalide" });

  const drawnSet = new Set(state.drawn);
  const cardsToCheck = [generateCard(pseudo + "#" + state.gameId)];
  if (player.isSub) cardsToCheck.push(generateCard(pseudo + "#sub#" + state.gameId));

  let eligible = false;
  for (const grid of cardsToCheck) {
    const numberOnCard = grid.some((row) => row.includes(n));
    const notYetDrawn = !drawnSet.has(n);
    const totalRemaining = grid.flat().filter((v) => !drawnSet.has(v)).length;
    const closeEnough = totalRemaining <= 3;
    if (numberOnCard && notYetDrawn && closeEnough) {
      eligible = true;
      break;
    }
  }

  if (eligible) {
    const now = Date.now();
    if (ballLog.gameId !== state.gameId) ballLog = { gameId: state.gameId, byPseudo: {} };
    const mine = ballLog.byPseudo[pseudo] || (ballLog.byPseudo[pseudo] = { last: 0, numbers: [] });

    // 1) même numéro déjà lâché pendant cette partie
    if (mine.numbers.includes(n)) {
      return res.json({ ok: true, eligible: false, rejected: "already" });
    }
    // 2) trop tôt après ta dernière boule
    const wait = mine.last + BALL_COOLDOWN_MS - now;
    if (wait > 0) {
      return res.json({ ok: true, eligible: false, rejected: "cooldown", retryAfterMs: wait });
    }
    // 3) trop de boules déjà à l'écran
    const onScreen = state.ballDrops.filter((b) => now - b.ts < BALL_VISIBLE_MS).length;
    if (onScreen >= MAX_BALLS_ON_SCREEN) {
      return res.json({ ok: true, eligible: false, rejected: "busy", retryAfterMs: 3000 });
    }

    mine.last = now;
    mine.numbers.push(n);
    state.ballDrops.push({
      id: now + "-" + Math.random().toString(36).slice(2, 8),
      pseudo,
      number: n,
      ts: now,
      ...getPublicStatus(pseudo),
    });
  }
  res.json({ ok: true, eligible });
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
  state = { drawn: [], players: [], tierWinners: { 1: null, 2: null, 3: null }, winner: null, pendingFinalists: [], pendingFinalistsDrawCount: null, wheelSpin: null, started: true, gameId: newGameId(), ballDrops: [], duckEvent: null, panDrops: [] };
  res.json({ ok: true });
});

// Easter egg déclenché manuellement par le streamer/un modérateur (bouton
// "🦆 Faire voler le canard" dans les contrôles streamer) : fait traverser
// l'écran à un canard, pour tous les viewers, sans lien avec le tirage des
// numéros. Comme pour /start-wheel-spin, on se contente de poser un
// événement avec un id unique — c'est overlay.js (detectDuckEvent) qui
// détecte le changement d'id au sondage suivant et joue l'animation.
app.post("/trigger-duck", (req, res) => {
  if (!checkAdmin(req, res)) return;
  state.duckEvent = {
    id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
    ts: Date.now(),
  };
  res.json({ ok: true, duckEvent: state.duckEvent });
});

app.post("/start-wheel-spin", (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { names } = req.body || {};
  if (!Array.isArray(names) || names.length < 2) {
    return res.status(400).json({ error: "il faut au moins 2 pseudos" });
  }
  const winnerIndex = Math.floor(Math.random() * names.length);
  const winnerLabel = names[winnerIndex];
  // Le label peut être "pseudo" ou "pseudo (bonus)" — utile quand une même
  // personne est ex-æquo entre son carton principal et son carton bonus.
  const isBonus = winnerLabel.endsWith(" (bonus)");
  const winnerPseudo = isBonus ? winnerLabel.slice(0, -" (bonus)".length) : winnerLabel;
  const match = (state.pendingFinalists || []).find(
    (f) => f.pseudo === winnerPseudo && (isBonus ? f.cardType === "bonus" : f.cardType !== "bonus")
  );

  const isSuper = (state.pendingFinalistsDrawCount ?? state.drawn.length) <= SUPER_THRESHOLD;
  const finalWinnerPseudo = match ? match.pseudo : winnerPseudo;
  if (isSuper) grantFrame(finalWinnerPseudo, SUPER_FRAME_KEY);
  recordWin(finalWinnerPseudo, isSuper);
  state.winner = match
    ? { pseudo: match.pseudo, cardType: match.cardType, isSuper, ...getPublicStatus(finalWinnerPseudo) }
    : { pseudo: winnerPseudo, cardType: "principal", isSuper, ...getPublicStatus(finalWinnerPseudo) };
  state.pendingFinalists = [];
  state.pendingFinalistsDrawCount = null;
  state.wheelSpin = {
    id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
    names,
    winnerIndex,
    ts: Date.now(),
  };
  res.json({ ok: true, winner: state.winner, wheelSpin: state.wheelSpin });
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
      // tags["user-id"] est l'identifiant Twitch stable du viewer (ne change
      // jamais, contrairement au pseudo) : sert à détecter un renommage et à
      // rapatrier ses cadres/victoires sur le nouveau pseudo automatiquement.
      reconcilePseudoRename(tags["user-id"], pseudo);
      const result = registerPlayerInternal(pseudo, isSub);
      if (result.ok) {
        client.say(channel, "@" + pseudo + " tu es inscrit(e) au Carthon Plein 🐟 va voir ton carton dans le panneau de l'extension !");
      } else {
        client.say(channel, "@" + pseudo + " les inscriptions sont fermées pour cette partie, à la prochaine !");
      }
      return;
    }
    if (text === "!pan") {
      // Easter egg ouvert à tout le chat (pas besoin d'être inscrit) : fait
      // apparaître une explosion à un endroit/taille aléatoires sur
      // l'overlay. Un cooldown global évite qu'un enchaînement de "!pan"
      // par plusieurs viewers ne sature l'écran.
      const now = Date.now();
      if (now - lastPanTriggerTs < PAN_COOLDOWN_MS) return;
      lastPanTriggerTs = now;
      state.panDrops.push({
        id: now + "-" + Math.random().toString(36).slice(2, 8),
        ts: now,
      });
      return;
    }
    // La commande "!23" (boule à l'écran) a été retirée : remplacée par un
    // double-clic directement sur le numéro manquant dans "Mon carton"
    // (voir POST /drop-ball) — plus rapide que taper une commande, surtout
    // en fin de partie quand plusieurs numéros approchent en même temps.
  });
} else {
  console.log("Bot de chat non configuré (BOT_USERNAME / BOT_OAUTH_TOKEN / CHANNEL_NAME manquants) — l'inscription par bouton reste disponible.");
}

(async () => {
  unlockedFramesByPseudo = await redisGetJSON("unlockedFramesByPseudo", {});
  displayChoiceByPseudo = await redisGetJSON("displayChoiceByPseudo", {});
  winsByPseudo = await redisGetJSON("winsByPseudo", {});
  pseudoByUserId = await redisGetJSON("pseudoByUserId", {});
  overlayVisible = await redisGetJSON("overlayVisible", true);
  console.log(
    REDIS_ENABLED
      ? "Stockage persistant Redis connecté — cadres/badges/titres restaurés."
      : "⚠️ Redis non configuré (UPSTASH_REDIS_REST_URL/TOKEN manquants) — les cadres/badges/titres ne survivront PAS à un redémarrage."
  );

  app.listen(PORT, () => {
    console.log("Serveur démarré sur le port " + PORT);
  });
})();
