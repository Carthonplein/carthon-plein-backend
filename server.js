const express = require("express");
const cors = require("cors");
const tmi = require("tmi.js");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1); // Render est derrière un proxy : sert à lire la vraie adresse IP du visiteur
app.use(cors());
app.use(express.json({ limit: "20kb" }));

// Limiteur de débit simple (en mémoire) : protège contre quelqu'un qui martèlerait le serveur
// (par ex. pour épuiser le quota de l'API Twitch). Les plafonds sont larges pour ne jamais
// gêner de vrais viewers, même plusieurs derrière la même box internet.
const rateBuckets = new Map();
function rateLimit(name, max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const key = name + "|" + (req.ip || "?");
    let e = rateBuckets.get(key);
    if (!e || now > e.reset) { e = { n: 0, reset: now + windowMs }; rateBuckets.set(key, e); }
    e.n += 1;
    if (e.n > max) return res.status(429).json({ error: "trop de requêtes, réessaie dans un instant" });
    next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, e] of rateBuckets) if (now > e.reset) rateBuckets.delete(k); }, 60000).unref();

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
// Garde-fou de chaîne : l'extension étant publique, n'importe quel streamer peut l'installer
// et Twitch lui signe alors un token valide (role "broadcaster" pour SA chaîne). On n'accepte
// donc que les tokens émis pour NOTRE chaîne (champ channel_id du token). L'identifiant est
// soit ALLOWED_CHANNEL_ID (variable Render, optionnelle), soit résolu automatiquement depuis
// CHANNEL_NAME au démarrage. Sans aucun des deux, la vérification est désactivée.
let allowedChannelId = process.env.ALLOWED_CHANNEL_ID || null;
const CHANNEL_GUARD_ON = !!(process.env.ALLOWED_CHANNEL_ID || process.env.CHANNEL_NAME);

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
    // Token d'une autre chaîne (ou ID de notre chaîne pas encore résolu) : refusé
    if (CHANNEL_GUARD_ON && (!allowedChannelId || String(payload.channel_id) !== String(allowedChannelId))) return null;
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

// Lecture avec nouvelles tentatives. Distingue "la clé n'existe pas" (normal au tout premier
// démarrage : on renvoie la valeur par défaut) d'une ERREUR de lecture : dans ce second cas la
// clé est marquée "illisible" et plus jamais écrasée (voir redisSetJSON), pour qu'une panne
// passagère de Redis ne puisse jamais effacer les cadres/victoires des joueurs.
const redisUnreadable = new Set();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const RETRY_BASE_MS = Number(process.env.REDIS_RETRY_MS || 1500);

async function redisGetJSON(key, fallback, attempts) {
  if (!REDIS_ENABLED) return fallback;
  const maxTries = attempts || 1;
  for (let i = 1; i <= maxTries; i++) {
    try {
      const res = await fetch(REDIS_URL + "/get/" + encodeURIComponent(key), {
        headers: { Authorization: "Bearer " + REDIS_TOKEN },
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (data && data.error) throw new Error(data.error);
      redisUnreadable.delete(key);
      return data && data.result ? JSON.parse(data.result) : fallback;
    } catch (e) {
      console.error("Erreur lecture Redis (" + key + ") essai " + i + "/" + maxTries + " :", e.message);
      if (i < maxTries) await sleep(RETRY_BASE_MS * i);
    }
  }
  redisUnreadable.add(key);
  return fallback;
}

// Écritures : (1) rien n'est écrit avant la fin du chargement initial (sinon une écriture
// précoce, par ex. un message de chat reçu pendant le démarrage, écraserait tout avec presque
// rien), (2) jamais sur une clé qu'on n'a pas pu relire, (3) une seule écriture à la fois par
// clé et toujours la plus récente (pas de désordre), (4) nouvelles tentatives si Redis répond
// mal, avec un message dans les logs si ça échoue vraiment.
let dataReady = false;
const writeState = new Map(); // key -> { running, dirty, value }

async function flushKey(key) {
  const st = writeState.get(key);
  st.running = true;
  while (st.dirty) {
    st.dirty = false;
    let ok = false;
    for (let i = 1; i <= 3 && !ok; i++) {
      try {
        const res = await fetch(REDIS_URL + "/set/" + encodeURIComponent(key), {
          method: "POST",
          headers: { Authorization: "Bearer " + REDIS_TOKEN },
          body: JSON.stringify(st.value),
        });
        ok = res.ok;
        if (!ok) console.error("Erreur écriture Redis (" + key + ") : HTTP " + res.status);
      } catch (e) {
        console.error("Erreur écriture Redis (" + key + ") :", e.message);
      }
      if (!ok && i < 3) await sleep(1000 * i);
    }
    if (!ok) console.error("⚠️ ÉCHEC d'écriture Redis pour " + key + " après 3 essais — la prochaine modification réessaiera.");
  }
  st.running = false;
}

function redisSetJSON(key, value) {
  if (!REDIS_ENABLED) return Promise.resolve();
  if (!dataReady) return Promise.resolve();
  if (redisUnreadable.has(key)) {
    console.error("Écriture Redis ignorée pour " + key + " : la clé n'a pas pu être relue (protection contre l'écrasement).");
    return Promise.resolve();
  }
  const st = writeState.get(key) || { running: false, dirty: false, value: null };
  st.value = value;
  st.dirty = true;
  writeState.set(key, st);
  return st.running ? Promise.resolve() : flushKey(key);
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
  registrationEndsAt: null, // minuteur d'inscription (ms depuis 1970) ou null, fixé par "Nouvelle partie"
  gameId: newGameId(),
  ballDrops: [], // { id, pseudo, number, ts } — effet visuel "!numero", purgé après quelques secondes
  miniGame: null, // mini-jeu en cours { id, type, ts, winner } (ex. bouteille de pastis au n°51)
  duckEvent: null, // { id, ts } — easter egg "canard volant" (extension v114 : bouton du streamer), conservé pour compatibilité
  miniPoints: {}, // points cumulés aux mini-jeux de la partie : { userId: { userId, pseudo, pts, firsts, lastTs } }
  miniBonus: null, // { pseudo, points } : meilleur joueur des mini-jeux de la partie précédente => carton bonus pour CETTE partie
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
const PURCHASABLE_FRAMES = ["rock", "poop", "sea", "disco", "dino", "western", "cosy", "psy", "noel", "valentine", "easter", "pirate", "space", "formula1", "halloween", "nature"];

// Cadres saisonniers PAS ENCORE distribuables : ils ne comptent pas pour le titre
// "Grand Collectionneur". Quand la saison arrive (ex. Noël en décembre), retire simplement
// le nom de cette liste : le cadre devient alors obligatoire pour ce titre.
const SEASONAL_FRAMES_LOCKED = ["noel", "valentine", "easter"];

// Choix d'affichage de chaque viewer (badge/titre qu'il a sélectionné parmi
// ceux disponibles) — comme unlockedFramesByPseudo, chargé/sauvé sur Redis.
let displayChoiceByPseudo = {};

// Nombre de victoires par pseudo — { pseudo: { total: N, super: M } } —
// persisté sur Redis comme le reste, pour les titres basés sur les gains.
let winsByPseudo = {};

// Parties jouées par pseudo — { pseudo: { games: N, pioneer: true|false } } —
// pour les titres Fidèle / Pilier de la chaîne / Pionnier. Une partie compte
// quand elle se termine par "Nouvelle partie" ET qu'au moins un numéro a été
// tiré ; tous les inscrits de cette partie la comptent.
// Pionnier : avoir joué une partie qui se termine pendant la soirée de lancement
// (1er novembre 2026, heure de Paris). Dates modifiables ici.
const PIONEER_FROM = Date.parse("2026-10-31T23:00:00Z");  // 1er nov. 00h00 Paris
const PIONEER_UNTIL = Date.parse("2026-11-01T23:00:00Z"); // 2 nov. 00h00 Paris
let gamesByPseudo = {};

// Les 5 nouveaux titres (Vétéran, Fashion Victim, Fidèle, Pilier de la chaîne, Pionnier)
// ne sont connus que des versions récentes de l'extension (v117 et +). Tant que la
// version en ligne sur Twitch est plus ancienne, ils s'afficheraient comme "undefined"
// dans le sélecteur de titre : on les MASQUE donc, mais les compteurs (parties jouées,
// Pionnier de la soirée de lancement) continuent de tourner en coulisses.
// Pour les activer : variable d'environnement NEW_TITLES_VISIBLE = 1 sur Render
// (une fois la nouvelle version de l'extension en ligne).
const NEW_TITLES_VISIBLE = process.env.NEW_TITLES_VISIBLE === "1";
const NEW_TITLE_KEYS = ["veteran", "fashion_victim", "fidele", "pilier", "pionnier"];

function recordGameParticipation() {
  if (!state.drawn || state.drawn.length === 0) return;
  const now = Date.now();
  const isLaunchNight = now >= PIONEER_FROM && now < PIONEER_UNTIL;
  state.players.forEach((p) => {
    const g = gamesByPseudo[p.pseudo] || { games: 0, pioneer: false };
    g.games += 1;
    if (isLaunchNight) g.pioneer = true;
    gamesByPseudo[p.pseudo] = g;
  });
  redisSetJSON("gamesByPseudo", gamesByPseudo);
}

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
    if (gamesByPseudo[oldPseudo]) {
      const pn = gamesByPseudo[newPseudo] || { games: 0, pioneer: false };
      const po = gamesByPseudo[oldPseudo];
      gamesByPseudo[newPseudo] = { games: pn.games + po.games, pioneer: pn.pioneer || po.pioneer };
      delete gamesByPseudo[oldPseudo];
      redisSetJSON("gamesByPseudo", gamesByPseudo);
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
let overlayDelayMs = 0; // décalage ajouté par le streamer à l'affichage des viewers (en plus du retard vidéo mesuré par Twitch)
let overlayVolume = 1; // volume des sons de l'overlay pour tous les viewers (0 à 1), réglé par le streamer

// Dernier gagnant d'un Carthon Plein, mémorisé quand le streamer lance une
// "Nouvelle partie" (sinon son nom disparaîtrait avec le reste de `state`).
// Volontairement hors de `state` et persisté sur Redis, comme les cadres.
// { pseudo, cardType, isSuper, drawCount, playerCount, ts } — le badge/titre affiché est
// recalculé à chaque lecture (voir /state) pour rester à jour.
let lastWinner = null;

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
  const wins = isBroadcaster ? { total: 10, super: 2 } : (winsByPseudo[pseudo] || { total: 0, super: 0 });
  const played = isBroadcaster ? { games: 50, pioneer: true } : (gamesByPseudo[pseudo] || { games: 0, pioneer: false });

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
  if (wins.total >= 10) availableTitles.push("veteran");
  if (wins.total >= 3) availableTitles.push("multi_champion");
  const requiredForGrand = PURCHASABLE_FRAMES.filter((f) => !SEASONAL_FRAMES_LOCKED.includes(f));
  if (requiredForGrand.length > 0 && requiredForGrand.every((f) => ownedPurchasable.includes(f))) availableTitles.push("grand_collector");
  if (played.games >= 50) availableTitles.push("pilier");
  if (ownedPurchasable.length >= 5) availableTitles.push("fashion_victim");
  if (wins.total >= 1) availableTitles.push("chanceux");
  if (played.games >= 10) availableTitles.push("fidele");
  if (played.pioneer) availableTitles.push("pionnier");
  if (isBroadcaster || frames.length >= 2) availableTitles.push("collector");

  return {
    availableBadges,
    availableTitles: NEW_TITLES_VISIBLE ? availableTitles : availableTitles.filter((t) => !NEW_TITLE_KEYS.includes(t)),
  };
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

// ---------- Carton bonus gagné aux mini-jeux ----------
// Chaque mini-jeu rapporte des points à ses 3 premiers (3 / 2 / 1). À la fin de la partie ("Nouvelle partie"), le
// joueur qui a le plus de points reçoit un carton bonus, valable uniquement pour la partie suivante.
// Un abonné champion reçoit un 3e carton (en plus de son carton bonus abonné).
const MINI_POINTS = [3, 2, 1];
function awardMiniPoints(entries) {
  entries.slice(0, 3).forEach((e, i) => {
    if (!e || !e.userId) return;
    const cur = state.miniPoints[e.userId] || (state.miniPoints[e.userId] = { userId: e.userId, pseudo: null, pts: 0, firsts: 0, lastTs: 0 });
    if (e.pseudo && e.pseudo !== "Un viewer") cur.pseudo = e.pseudo;
    cur.pts += MINI_POINTS[i];
    if (i === 0) cur.firsts++;
    cur.lastTs = Date.now();
  });
}
function miniRanking() {
  return Object.values(state.miniPoints).sort((a, b) => b.pts - a.pts || b.firsts - a.firsts || a.lastTs - b.lastTs);
}
function hasMiniBonus(pseudo) {
  return !!(state.miniBonus && state.miniBonus.pseudo && String(pseudo).toLowerCase() === state.miniBonus.pseudo.toLowerCase());
}
function playerHasBonusCard(p) { return !!(p && (p.isSub || p.hasBonus)); }
// 3e carton : un abonné qui est aussi champion des mini-jeux garde son carton bonus abonné ET reçoit un carton mini-jeux.
function playerHasMiniCard(p) { return !!(p && p.isSub && p.hasBonus); }

function computeEntrants() {
  const entrants = [];
  for (const p of state.players) {
    entrants.push({ pseudo: p.pseudo, cardType: "principal", grid: generateCard(p.pseudo + "#" + state.gameId) });
    if (playerHasBonusCard(p)) entrants.push({ pseudo: p.pseudo, cardType: "bonus", grid: generateCard(p.pseudo + "#sub#" + state.gameId) });
    if (playerHasMiniCard(p)) entrants.push({ pseudo: p.pseudo, cardType: "bonus", grid: generateCard(p.pseudo + "#mini#" + state.gameId) });
  }
  return entrants;
}

// Classement complet (pas seulement le top 3) : un seul carton par pseudo
// (le meilleur des deux si abonné), trié par proximité du Carthon Plein.
function computeFullStandings(drawnSet) {
  const bestByPseudo = new Map();
  for (const p of state.players) {
    const cards = [{ cardType: "principal", grid: generateCard(p.pseudo + "#" + state.gameId) }];
    if (playerHasBonusCard(p)) cards.push({ cardType: "bonus", grid: generateCard(p.pseudo + "#sub#" + state.gameId) });
    if (playerHasMiniCard(p)) cards.push({ cardType: "bonus", grid: generateCard(p.pseudo + "#mini#" + state.gameId) });
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
  return payload;
}

// Nettoyage défensif d'un pseudo : un vrai pseudo Twitch ne contient jamais ces caractères,
// donc pour un joueur normal rien ne change ; ça empêche seulement d'injecter du HTML.
function cleanPseudo(s) {
  return String(s == null ? "" : s).replace(/[<>&"'`\\]/g, "").replace(/\s+/g, " ").trim().slice(0, 40);
}

// Les inscriptions sont ouvertes tant que la partie n'a pas commencé ET que le minuteur
// (s'il y en a un) n'est pas écoulé.
function registrationIsOpen() {
  if (gamePhase() !== "lobby") return false;
  if (state.registrationEndsAt && Date.now() >= state.registrationEndsAt) return false;
  return true;
}

// Inscription partagée entre le bouton du panel (HTTP) et la commande de chat
function registerPlayerInternal(pseudo, isSub) {
  pseudo = cleanPseudo(pseudo);
  if (!pseudo) return { ok: false, reason: "invalid" };
  if (gamePhase() !== "lobby") return { ok: false, reason: "closed" };
  if (!registrationIsOpen()) return { ok: false, reason: "closed" };
  if (!state.players.some((p) => p.pseudo === pseudo)) {
    state.players.push({ pseudo, isSub: !!isSub, hasBonus: hasMiniBonus(pseudo) });
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
  <p><em>Dernière mise à jour : octobre 2026</em></p>
  <h2>Ce que l'extension utilise et enregistre</h2>
  <p>Carthon Plein est une extension Twitch de loto/bingo interactif, gratuite, qui s'affiche par-dessus le stream de la chaîne carthonplein. Pour fonctionner, elle utilise et conserve :</p>
  <ul>
    <li>Votre pseudo Twitch, obtenu via l'autorisation d'identité Twitch (vous n'êtes jamais obligé de la donner : sans elle, vous pouvez regarder la partie mais pas jouer). Il sert à générer votre carton, à l'afficher dans le classement et à annoncer les gagnants.</li>
    <li>Votre statut d'abonné à la chaîne (le cas échéant), pour vous attribuer un carton bonus.</li>
    <li>Votre progression dans le jeu, conservée d'une partie à l'autre : les cadres de carton débloqués, le nombre de victoires, le nombre de parties jouées, le fait d'avoir joué la soirée de lancement, ainsi que le cadre et le titre que vous avez choisi d'afficher. Ces informations servent uniquement à vous attribuer vos cadres et vos titres.</li>
  </ul>
  <h2>Où sont stockées les données</h2>
  <p>Les données sont hébergées sur des serveurs situés aux États-Unis (hébergeur Render pour le serveur du jeu, base de données Upstash Redis pour le stockage). Des copies de sauvegarde quotidiennes sont faites pour éviter de perdre les cadres et les victoires des joueurs.</p>
  <h2>Ce que l'extension NE fait PAS</h2>
  <ul>
    <li>Elle ne collecte ni adresse e-mail, ni nom réel, ni donnée de paiement, ni autre donnée personnelle que celles listées ci-dessus.</li>
    <li>Elle ne vend et ne partage aucune information avec des tiers, en dehors des hébergeurs techniques cités plus haut.</li>
    <li>Elle n'utilise aucun cookie de suivi et aucune publicité.</li>
  </ul>
  <h2>Vos droits</h2>
  <p>Vous pouvez demander à tout moment l'accès à vos données, leur correction ou leur suppression (pseudo, cadres, victoires, parties jouées) en écrivant à l'adresse ci-dessous.</p>
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
  <p>Pour participer, le viewer clique sur le bouton "S'inscrire" de l'extension, affichée par-dessus le stream, pendant qu'une partie est ouverte aux inscriptions (ce qui nécessite d'autoriser l'extension à connaître son pseudo Twitch). Un carton personnel est alors généré. Les mini-jeux gratuits (jeux d'adresse déclenchés par certains numéros, sans aucun effet sur le tirage des numéros) rapportent des points à leurs trois premiers ; à la fin de la partie, le joueur ayant le plus de points reçoit un carton bonus, valable uniquement pour la partie suivante. Les inscriptions peuvent être limitées dans le temps par un minuteur affiché à l'écran, et se ferment dans tous les cas dès le premier numéro tiré. Le streamer tire ensuite des numéros parmi 1 et 75. Les joueurs abonnés à la chaîne reçoivent en plus un carton bonus, sans surcoût ni condition supplémentaire. La partie se termine lorsqu'un joueur complète l'intégralité de son carton ("Carthon Plein").</p>

  <h2>Article 4 — Détermination du/des gagnant(s)</h2>
  <p>Le gagnant est le premier joueur dont le carton (principal ou bonus) est entièrement complété. En cas de complétion simultanée par plusieurs joueurs différents, un tirage au sort transparent (roue visible en direct par tous les viewers) désigne le gagnant final. Si un même joueur complète simultanément son carton principal et son carton bonus, sans qu'aucun autre joueur ne soit également ex-æquo, il est déclaré gagnant directement, sans tirage au sort.</p>

  <h2>Article 5 — Lots</h2>
  <p>La nature des lots (goodies, cartes cadeaux, etc.) est annoncée par l'organisateur avant ou pendant chaque partie. Les lots ne sont ni échangeables, ni remboursables, ni convertibles en espèces. L'organisateur se réserve le droit de modifier la nature des lots proposés d'une partie à l'autre.</p>

  <h2>Article 6 — Participants mineurs</h2>
  <p>La participation au jeu lui-même est ouverte sans condition d'âge. En revanche, si un gagnant est mineur, la remise du lot est conditionnée à l'accord explicite d'un parent ou représentant légal, qui devra être en copie des échanges relatifs à l'envoi du lot.</p>

  <h2 id="donnees">Article 7 — Données personnelles</h2>
  <p>Pour fonctionner, l'extension utilise et conserve :</p>
  <ul>
    <li>le pseudo Twitch du joueur, obtenu via l'autorisation d'identité Twitch donnée lors de l'inscription (sans cette autorisation, il est possible de regarder la partie mais pas d'y participer) : il sert à générer le carton, à l'afficher dans le classement et à annoncer les gagnants ;</li>
    <li>le statut d'abonné à la chaîne, pour attribuer le carton bonus ;</li>
    <li>la progression du joueur d'une partie à l'autre : cadres de carton débloqués, nombre de victoires, nombre de parties jouées, participation à la soirée de lancement, cadre et titre choisis pour l'affichage. Ces informations servent uniquement à attribuer les cadres et les titres ;</li>
    <li>en cas de gain d'un lot physique, une adresse postale, demandée uniquement au gagnant et utilisée exclusivement pour l'envoi du lot. Elle n'est conservée que le temps nécessaire à l'expédition, puis supprimée.</li>
  </ul>
  <p>Ces données sont hébergées sur des serveurs situés aux États-Unis (Render pour le serveur du jeu, Upstash Redis pour le stockage), avec des sauvegardes quotidiennes pour éviter de perdre les cadres et les victoires des joueurs. Aucune donnée n'est vendue ni partagée avec des tiers en dehors de ces hébergeurs techniques ; l'extension n'utilise ni cookie de suivi ni publicité.</p>
  <p>Chaque joueur peut demander à tout moment l'accès à ses données, leur correction ou leur suppression (pseudo, cadres, victoires, parties jouées) en écrivant à carthonplein@gmail.com.</p>

  <h2>Article 8 — Responsabilité</h2>
  <p>Ce jeu est organisé par la chaîne Carthon Plein et n'est ni sponsorisé, ni géré, ni associé à Twitch Interactive, Inc. L'organisateur ne saurait être tenu responsable en cas de dysfonctionnement technique indépendant de sa volonté (panne, coupure internet, bug de l'extension) empêchant le bon déroulement d'une partie.</p>

  <h2>Article 9 — Modification du règlement</h2>
  <p>L'organisateur se réserve le droit de modifier, suspendre ou annuler le jeu à tout moment si les circonstances l'exigent, sans que sa responsabilité puisse être engagée de ce fait. Toute modification du présent règlement sera annoncée sur la chaîne.</p>

  <h2>Article 10 — Droit applicable</h2>
  <p>Le présent règlement est soumis au droit français. Toute contestation relative à son application devra être adressée à carthonplein@gmail.com avant toute autre démarche.</p>
</body>
</html>`);
});

app.get("/state", rateLimit("state", 900, 60000), (req, res) => {
  const drawnSet = new Set(state.drawn);
  // ne garde que les chutes de boules récentes (10 dernières secondes)
  const now = Date.now();
  state.ballDrops = state.ballDrops.filter((b) => now - b.ts < 10000);
  state.panDrops = state.panDrops.filter((p) => now - p.ts < 10000);
  res.json({
    drawn: state.drawn,
    players: state.players.map((p) => ({ pseudo: p.pseudo, isSub: p.isSub, hasBonus: !!p.hasBonus })),
    duckEvent: state.duckEvent,
    miniBonus: state.miniBonus,
    miniLeaders: miniRanking().filter((e) => e.pseudo).slice(0, 10).map((e) => ({ pseudo: e.pseudo, pts: e.pts })),
    gamePhase: gamePhase(),
    registrationOpen: registrationIsOpen(),
    registrationEndsAt: state.registrationEndsAt,
    serverTime: Date.now(),
    overlayVolume,
    overlayDelayMs,
    started: state.started,
    tierWinners: state.tierWinners,
    winner: state.winner,
    pendingFinalists: state.pendingFinalists,
    wheelSpin: state.wheelSpin,
    leaderboard: computeLeaderboard(drawnSet),
    ballDrops: state.ballDrops,
    gameId: state.gameId,
    overlayVisible,
    lockedFrames: SEASONAL_FRAMES_LOCKED,
    miniGame: publicMiniGame(),
    panDrops: state.panDrops,
    lastWinner: lastWinner ? { ...lastWinner, ...getPublicStatus(lastWinner.pseudo) } : null,
  });
});

// Ancienne inscription manuelle (pseudo + isSub libres, sans aucune vérification) : plus
// utilisée par l'extension (inscription par identité Twitch via /register-by-identity, ou
// par le chat avec !carthon). Désactivée car n'importe qui pouvait s'inscrire sous un faux
// pseudo ou se déclarer abonné pour obtenir un carton bonus.
app.post("/register", (req, res) => {
  res.status(410).json({ error: "route désactivée" });
});

app.get("/card/:pseudo", rateLimit("card", 600, 60000), (req, res) => {
  const pseudo = req.params.pseudo;
  const player = state.players.find((p) => p.pseudo === pseudo);
  const unlockedFrames = unlockedFramesByPseudo[pseudo] || [];
  const { availableBadges, availableTitles } = getAvailableStatuses(pseudo);
  const displayChoice = displayChoiceByPseudo[pseudo] || {};
  if (!player) {
    return res.json({ registered: false, unlockedFrames, availableBadges, availableTitles, displayChoice });
  }
  const grid = generateCard(pseudo + "#" + state.gameId);
  const bonusGrid = playerHasBonusCard(player) ? generateCard(pseudo + "#sub#" + state.gameId) : null;
  const miniGrid = playerHasMiniCard(player) ? generateCard(pseudo + "#mini#" + state.gameId) : null;
  const drawnSet = new Set(state.drawn);
  const myStanding = getStandingFor(pseudo, drawnSet);
  // Position du viewer au classement des mini-jeux (affichée s'il n'est pas dans le top 3 public).
  let miniMe = null;
  { const mr = miniRanking(); const idx = mr.findIndex((e) => e.pseudo && e.pseudo.toLowerCase() === pseudo.toLowerCase()); if (idx >= 0) miniMe = { rank: idx + 1, pts: mr[idx].pts }; }
  res.json({ registered: true, grid, bonusGrid, miniGrid, miniMe, unlockedFrames, availableBadges, availableTitles, displayChoice, myStanding });
});

app.post("/set-display-choice", rateLimit("display", 60, 60000), async (req, res) => {
  const { pseudo: rawPseudo, frame, title } = req.body || {};
  if (!rawPseudo || typeof rawPseudo !== "string") {
    return res.status(400).json({ error: "pseudo manquant" });
  }
  const pseudo = cleanPseudo(rawPseudo);
  if (!pseudo) return res.status(400).json({ error: "pseudo manquant" });
  // Vérification d'identité : si le client envoie son jeton Twitch signé, le pseudo doit être
  // celui de CE compte (on ne peut plus changer le cadre/titre d'un autre joueur). Les anciennes
  // versions de l'extension n'envoient pas de jeton : acceptées tant que STRICT_DISPLAY_AUTH
  // n'est pas activé sur Render (à activer une fois la nouvelle version en ligne).
  {
    const authHeader = req.headers["authorization"] || "";
    const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    const payload = tok ? verifyTwitchExtensionToken(tok) : null;
    if (payload && payload.user_id && /^\d+$/.test(String(payload.user_id))) {
      const owner = await pseudoFromUserId(String(payload.user_id));
      if (owner && owner !== pseudo) return res.status(403).json({ error: "ce n'est pas ton pseudo" });
    } else if (process.env.STRICT_DISPLAY_AUTH === "1") {
      return res.status(401).json({ error: "identité Twitch requise" });
    }
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

// Volume des sons de l'overlay pour TOUS les viewers (0 à 100), réglé par le streamer/modérateur.
app.post("/set-delay", rateLimit("setdelay", 60, 60000), (req, res) => {
  if (!checkAdmin(req, res)) return;
  const ms = Number(req.body && req.body.ms);
  if (!Number.isFinite(ms) || ms < 0 || ms > 20000) return res.status(400).json({ error: "décalage invalide (0 à 20000 ms)" });
  overlayDelayMs = Math.round(ms / 500) * 500;
  redisSetJSON("overlayDelayMs", overlayDelayMs);
  res.json({ ok: true, overlayDelayMs });
});

app.post("/set-volume", rateLimit("setvolume", 60, 60000), (req, res) => {
  if (!checkAdmin(req, res)) return;
  const v = Number(req.body && req.body.volume);
  if (!Number.isFinite(v) || v < 0 || v > 100) return res.status(400).json({ error: "volume invalide (0 à 100)" });
  overlayVolume = Math.round(v) / 100;
  redisSetJSON("overlayVolume", overlayVolume);
  res.json({ ok: true, overlayVolume });
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

app.post("/grant-frame", async (req, res) => {
  const admin = checkAdmin(req, res);
  if (!admin) return;
  const { pseudo: typedPseudo, frameKey } = req.body || {};
  const pseudo = typeof typedPseudo === "string" ? typedPseudo : null;
  if (!pseudo || typeof pseudo !== "string" || !frameKey || typeof frameKey !== "string") {
    return res.status(400).json({ error: "pseudo et frameKey requis" });
  }
  if (EXCLUSIVE_FRAMES.includes(frameKey)) {
    return res.status(400).json({ error: "ce cadre ne peut pas être distribué manuellement, il ne s'obtient qu'en le gagnant" });
  }
  if (SEASONAL_FRAMES_LOCKED.includes(frameKey)) {
    return res.status(400).json({ error: "ce cadre saisonnier n'est pas encore distribuable (retire-le de SEASONAL_FRAMES_LOCKED dans server.js à l'ouverture de sa saison)" });
  }
  if (!PURCHASABLE_FRAMES.includes(frameKey)) {
    return res.status(400).json({ error: "cadre inconnu" });
  }
  const r = await resolveTypedPseudo(pseudo);
  if (r.error) return res.status(404).json({ error: r.error });
  grantFrame(r.pseudo, frameKey);
  console.log("AUDIT grant-frame par " + (admin.user_id || "?") + " : " + frameKey + " -> " + r.pseudo + (r.unverified ? " (non vérifié chez Twitch)" : ""));
  res.json({ ok: true, pseudo: r.pseudo, unlockedFrames: unlockedFramesByPseudo[r.pseudo] });
});

app.post("/revoke-frame", async (req, res) => {
  const admin = checkAdmin(req, res);
  if (!admin) return;
  const { pseudo: typedPseudo, frameKey } = req.body || {};
  const pseudo = typeof typedPseudo === "string" ? typedPseudo : null;
  if (!pseudo || typeof pseudo !== "string" || !frameKey || typeof frameKey !== "string") {
    return res.status(400).json({ error: "pseudo et frameKey requis" });
  }
  const r = await resolveTypedPseudo(pseudo);
  if (r.error) return res.status(404).json({ error: r.error });
  revokeFrame(r.pseudo, frameKey);
  console.log("AUDIT revoke-frame par " + (admin.user_id || "?") + " : " + frameKey + " <- " + r.pseudo);
  res.json({ ok: true, pseudo: r.pseudo, unlockedFrames: unlockedFramesByPseudo[r.pseudo] || [] });
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

// Pseudo (display_name) d'un identifiant Twitch numérique : d'abord notre mémoire (joueurs déjà
// inscrits), sinon l'API Twitch. Renvoie null si introuvable.
async function pseudoFromUserId(userId) {
  if (pseudoByUserId[userId]) return pseudoByUserId[userId];
  try {
    const token = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?id=" + encodeURIComponent(userId), {
      headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + token },
    });
    const data = await r.json();
    const user = data.data && data.data[0];
    return user ? cleanPseudo(user.display_name) : null;
  } catch (e) {
    return null;
  }
}

// Le streamer tape un pseudo à la main pour donner/retirer un cadre : on évite que la casse
// ("carthonplein" au lieu de "CarthonPlein"), un "@" ou des espaces fassent atterrir le cadre
// sur une fausse entrée que le joueur ne verrait jamais. Ordre : pseudo déjà connu du serveur
// (insensible à la casse), puis recherche chez Twitch, sinon refus si Twitch dit que ce compte
// n'existe pas (faute de frappe), sinon (Twitch injoignable) on garde la saisie telle quelle.
async function resolveTypedPseudo(typed) {
  const t = cleanPseudo(String(typed).trim().replace(/^@+/, ""));
  if (!t) return { error: "pseudo vide" };
  const low = t.toLowerCase();
  const known = new Set([
    ...Object.keys(unlockedFramesByPseudo), ...Object.keys(displayChoiceByPseudo),
    ...Object.keys(winsByPseudo), ...Object.keys(gamesByPseudo),
    ...Object.values(pseudoByUserId), ...state.players.map((p) => p.pseudo),
  ]);
  for (const k of known) if (typeof k === "string" && k.toLowerCase() === low) return { pseudo: k };
  try {
    const token = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?login=" + encodeURIComponent(low), {
      headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + token },
    });
    if (r.ok) {
      const data = await r.json();
      const user = data.data && data.data[0];
      if (user) return { pseudo: cleanPseudo(user.display_name) };
      return { error: "aucun compte Twitch ne s'appelle « " + t + " » (faute de frappe ?)" };
    }
  } catch (e) { /* Twitch injoignable : on garde la saisie */ }
  return { pseudo: t, unverified: true };
}

app.get("/identify/:userId", rateLimit("identify", 60, 60000), async (req, res) => {
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
    res.json({ linked: true, pseudo: cleanPseudo(user.display_name) });
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
    // Sécurité : seul le propriétaire de la chaîne peut enregistrer ce jeton. Sans ce contrôle,
    // n'importe qui pourrait visiter cette adresse avec SON compte et remplacer le jeton du
    // streamer (les abonnés ne seraient plus reconnus, donc plus de carton bonus).
    if (CHANNEL_NAME) {
      const meRes = await fetch("https://api.twitch.tv/helix/users", {
        headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + data.access_token },
      });
      const me = meRes.ok ? await meRes.json() : null;
      const login = me && me.data && me.data[0] && me.data[0].login;
      if (!login || login.toLowerCase() !== CHANNEL_NAME.toLowerCase()) {
        return res.status(403).send("Refusé : ce compte Twitch n'est pas le propriétaire de la chaîne " + CHANNEL_NAME + ".");
      }
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

// Résout l'ID numérique de notre chaîne (CHANNEL_NAME) pour le garde-fou de chaîne.
// Réessaie toutes les 15 s tant que Twitch ne répond pas : pendant ce temps, les actions
// protégées par token sont refusées (par sécurité) mais le jeu public reste consultable.
async function resolveAllowedChannel() {
  if (allowedChannelId || !CHANNEL_GUARD_ON) return;
  const id = await getBroadcasterUserId();
  if (id) {
    allowedChannelId = String(id);
    console.log("Garde-fou de chaîne actif : seuls les tokens de la chaîne " + allowedChannelId + " sont acceptés.");
  } else {
    console.error("Garde-fou de chaîne : ID de la chaîne introuvable (CHANNEL_NAME correct ? Client Secret configuré ?) — nouvel essai dans 15 s.");
    setTimeout(resolveAllowedChannel, 15000);
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
app.post("/register-by-identity", rateLimit("register", 30, 60000), async (req, res) => {
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
    const pseudo = cleanPseudo(user.display_name);

    reconcilePseudoRename(userId, pseudo);
    const isSub = await checkIsSubscriber(userId);
    const result = registerPlayerInternal(pseudo, isSub);
    if (!result.ok) return res.status(403).json({ error: "inscriptions fermées pour cette partie" });

    const grid = generateCard(pseudo + "#" + state.gameId);
    const bonusGrid = (isSub || hasMiniBonus(pseudo)) ? generateCard(pseudo + "#sub#" + state.gameId) : null;
    const miniGrid = (isSub && hasMiniBonus(pseudo)) ? generateCard(pseudo + "#mini#" + state.gameId) : null;
    res.json({ ok: true, pseudo, isSub, grid, bonusGrid, miniGrid });
  } catch (e) {
    res.status(500).json({ error: "erreur serveur" });
  }
});

// ---------- Anti-spam des boules ----------
// Règles appliquées côté serveur (donc impossibles à contourner depuis le
// navigateur) :
//  - un joueur ne peut lâcher qu'UNE boule toutes les BALL_COOLDOWN_MS ;
//  - aucune limite par numéro : tant qu'il reste 3 numéros ou moins sur son carton, un
//    joueur peut refaire tomber le même numéro autant de fois qu'il veut (dans le respect
//    du délai ci-dessus) ;
//  - au plus MAX_BALLS_ON_SCREEN boules à l'écran en même temps (garde-fou
//    contre un afflux de comptes qui cliqueraient tous en même temps).
// Le suivi est lié à l'identifiant de la partie : "Nouvelle partie" remet
// tout à zéro automatiquement.
const BALL_COOLDOWN_MS = 8000;
const MAX_BALLS_ON_SCREEN = 15;
const BALL_VISIBLE_MS = 10000; // même durée que la purge dans /state
let ballLog = { gameId: null, byPseudo: {} }; // byPseudo[pseudo] = { last }

// ---------- Boule ("numéro proche") par double-clic (remplace "!23") ----------
// Même logique d'éligibilité que l'ancienne commande de chat (numéro sur le
// carton, pas encore tiré, et il reste 3 numéros ou moins sur l'ensemble du
// carton) — sauf que l'identité vient du token signé, jamais du client.
app.post("/drop-ball", rateLimit("drop", 90, 60000), (req, res) => {
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
  if (playerHasBonusCard(player)) cardsToCheck.push(generateCard(pseudo + "#sub#" + state.gameId));
  if (playerHasMiniCard(player)) cardsToCheck.push(generateCard(pseudo + "#mini#" + state.gameId));

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
    const mine = ballLog.byPseudo[pseudo] || (ballLog.byPseudo[pseudo] = { last: 0 });

    // 1) trop tôt après ta dernière boule
    const wait = mine.last + BALL_COOLDOWN_MS - now;
    if (wait > 0) {
      return res.json({ ok: true, eligible: false, rejected: "cooldown", retryAfterMs: wait });
    }
    // 2) trop de boules déjà à l'écran
    const onScreen = state.ballDrops.filter((b) => now - b.ts < BALL_VISIBLE_MS).length;
    if (onScreen >= MAX_BALLS_ON_SCREEN) {
      return res.json({ ok: true, eligible: false, rejected: "busy", retryAfterMs: 3000 });
    }

    mine.last = now;
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
  // Pas de mini-jeu sur le tirage qui termine la partie (Carthon Plein final, ou égalité à départager) : la bannière de victoire
  // et le classement des mini-jeux doivent s'afficher tout de suite, et le classement des mini-jeux doit être définitif.
  if (MINIGAME_BY_NUMBER[n] && gamePhase() !== "finished") startMiniGame(MINIGAME_BY_NUMBER[n]);
  res.json({ drawn: n });
});

// Easter egg "canard volant" de l'extension v114 (bouton "🦆 Faire voler le canard" du streamer) : route conservée
// pour que l'ancienne extension continue de fonctionner. La v131 n'utilise plus ce bouton (le canard est un mini-jeu au n°69).
app.post("/trigger-duck", (req, res) => {
  if (!checkAdmin(req, res)) return;
  state.duckEvent = {
    id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
    ts: Date.now(),
  };
  res.json({ ok: true, duckEvent: state.duckEvent });
});

app.post("/reset", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  // Meilleur joueur des mini-jeux de la partie qui se termine => carton bonus pour la partie qui commence.
  // Si la partie en cours n'a pas été jouée (aucun numéro tiré, aucun point), on garde le bonus déjà attribué (ex. : "Nouvelle partie" cliqué en fin de soirée, puis de nouveau la semaine suivante).
  let nextMiniBonus = state.drawn.length === 0 && !Object.keys(state.miniPoints || {}).length ? state.miniBonus || null : null;
  const best = miniRanking()[0];
  if (best && best.pts > 0) {
    const bp = best.pseudo || (await pseudoForUserId(best.userId));
    if (bp) nextMiniBonus = { pseudo: bp, points: best.pts };
  }
  // La partie qui se termine avait un gagnant : on le retient avant d'effacer l'état.
  // (Pas de gagnant, par exemple partie abandonnée : on garde le précédent.)
  if (state.winner && state.winner.pseudo) {
    lastWinner = {
      pseudo: state.winner.pseudo,
      cardType: state.winner.cardType || "principal",
      isSuper: !!state.winner.isSuper,
      drawCount: state.drawn.length,
      playerCount: state.players.length, // nombre d'inscrits de la partie qui se termine
      ts: Date.now(),
    };
    redisSetJSON("lastWinner", lastWinner);
  }
  recordGameParticipation();
  // Minuteur d'inscription facultatif (en secondes, 10 s à 30 min) choisi par le streamer.
  const regSecs = Math.floor(Number(req.body && req.body.registrationSeconds));
  const regEnd = regSecs >= 10 && regSecs <= 1800 ? Date.now() + regSecs * 1000 : null;
  state = { drawn: [], players: [], tierWinners: { 1: null, 2: null, 3: null }, winner: null, pendingFinalists: [], pendingFinalistsDrawCount: null, wheelSpin: null, started: true, gameId: newGameId(), ballDrops: [], miniGame: null, duckEvent: null, miniPoints: {}, miniBonus: nextMiniBonus, panDrops: [], registrationEndsAt: regEnd };
  res.json({ ok: true, miniBonus: nextMiniBonus });
});

// ---------- Mini-jeux ----------
// ===== Moteur de la course de voitures (IDENTIQUE côté client et serveur : le serveur rejoue les touches du joueur) =====
// Terrain de 100 x 140 unités ; 60 pas par seconde. Obstacles tirés d'un tirage fixe (graine) commun à tous.
const CAR_W = 100, CAR_H = 140, CAR_TPS = 60, CAR_MAX_TICKS = 5400;
const CAR_OBST = [{ w: 11, h: 16 }, { w: 22, h: 6 }, { w: 15, h: 28 }, { w: 6, h: 7 }]; // voiture, barrière, camion, cône
function makeCarSim(seed) {
  let a = (seed >>> 0) || 1;
  const rnd = () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const s = { t: 0, x: 46, y: 112, cw: 8, ch: 14, obs: [], next: 20, dead: false, rnd };
  s.step = function (dir) {
    if (s.dead) return true;
    const dx = Math.floor(dir / 3) - 1, dy = (dir % 3) - 1;
    s.x = Math.min(CAR_W - s.cw, Math.max(0, s.x + dx * 1.15));
    s.y = Math.min(CAR_H - s.ch - 2, Math.max(70, s.y + dy * 0.9));
    if (s.t >= s.next) {
      const k = Math.floor(rnd() * 4), o = CAR_OBST[k];
      s.obs.push({ k, x: rnd() * (CAR_W - o.w), y: -o.h, w: o.w, h: o.h });
      s.next = s.t + Math.max(14, Math.round((58 - s.t * 0.011) * (0.7 + rnd() * 0.6)));
    }
    const v = Math.min(3.2, 0.8 + s.t * 0.0008);
    for (const o of s.obs) o.y += v;
    s.obs = s.obs.filter((o) => o.y < CAR_H + 30);
    for (const o of s.obs) {
      if (o.x < s.x + s.cw - 1 && o.x + o.w > s.x + 1 && o.y < s.y + s.ch - 1 && o.y + o.h > s.y + 1) { s.dead = true; return true; }
    }
    s.t++;
    return false;
  };
  return s;
}
// Rejoue une liste d'événements [[tick, code],...] ; renvoie le nombre de pas survécus (CAR_MAX_TICKS = a tout tenu).
function carReplay(seed, events) {
  const s = makeCarSim(seed); let i = 0, dir = 4;
  while (s.t < CAR_MAX_TICKS) {
    while (i < events.length && events[i][0] <= s.t) { dir = events[i][1]; i++; }
    if (s.step(dir)) return s.t;
  }
  return CAR_MAX_TICKS;
}
// ===== fin du moteur =====
// ===== Moteur du jeu du poisson qui nage entre les rochers (IDENTIQUE côté client et serveur : le serveur rejoue les battements) =====
const FL_W = 160, FL_H = 100, FL_TPS = 60, FL_MAX_TICKS = 5400;
function makeFlapSim(seed) {
  let a = (seed >>> 0) || 1;
  const rnd = () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const s = { t: 0, x: 38, y: 42, vy: -1.5, fw: 9, fh: 6, pipes: [], next: 40, cy: 50, n: 0, passed: 0, dead: false };
  s.step = function (flap) {
    if (s.dead) return true;
    if (flap) s.vy = -1.5;
    s.vy = Math.min(2.4, s.vy + 0.085);
    s.y += s.vy;
    if (s.y < 0) { s.y = 0; s.vy = 0; }
    if (s.y + s.fh > FL_H - 6) { s.dead = true; return true; } // le fond marin
    const v = Math.min(1.7, 0.85 + s.t * 0.0003);
    if (s.t >= s.next) {
      const gap = Math.max(24, 34 - s.t * 0.002);
      const lo = gap / 2 + 9, hi = FL_H - 6 - gap / 2 - 9;
      s.cy = Math.min(hi, Math.max(lo, s.cy + (rnd() - 0.5) * 44));
      s.pipes.push({ x: FL_W, cy: s.cy, gap, w: 13, k: s.n++ % 3, ok: false });
      s.next = s.t + Math.round(64 / v);
    }
    for (const p of s.pipes) {
      p.x -= v;
      if (!p.ok && p.x + p.w < s.x) { p.ok = true; s.passed++; }
      if (p.x < s.x + s.fw - 1.5 && p.x + p.w > s.x + 1.5 && (s.y + 1 < p.cy - p.gap / 2 || s.y + s.fh - 1 > p.cy + p.gap / 2)) { s.dead = true; return true; }
    }
    s.pipes = s.pipes.filter((p) => p.x + p.w > -4);
    s.t++;
    return false;
  };
  return s;
}
// Rejoue une liste de ticks où le joueur a nagé ; renvoie le nombre de pas survécus.
function flapReplay(seed, flaps) {
  const s = makeFlapSim(seed); let i = 0;
  while (s.t < FL_MAX_TICKS) {
    let f = false;
    while (i < flaps.length && flaps[i] <= s.t) { if (flaps[i] === s.t) f = true; i++; }
    if (s.step(f)) return s.t;
  }
  return FL_MAX_TICKS;
}
// ===== fin du moteur du poisson =====

// Numéro tiré -> mini-jeu :
//   51 : pluie de bouteilles de pastis (~85 bouteilles rapides, chacune éclatée = 1 point) ; piège : toucher une bouteille de cola élimine le joueur (son score reste figé)
//   25 : pêche au thon (thon bleu +1, thon rouge +2, thon doré +5, requin -3)
//   69 : le canard fou : il file très vite dans tous les sens ; chacun essaie de le toucher, classement au temps mis
//   7  : puzzle du logo (20 pièces) : chacun le reconstitue seul, classement au temps
//   33 : mémoire de thons : 12 cartes (6 paires) à retrouver le plus vite possible, classement au temps
//   1  : course de voitures : flèches du clavier pour éviter des obstacles de plus en plus rapides ; le plus longtemps sans toucher gagne
//   75 : le poisson qui nage entre les rochers (style Flappy Bird) : flèche haut/clic pour donner un coup de nageoire ; le plus longtemps sans toucher gagne
//        (l'ancien jeu « Carthon Hero » est retiré du tirage)
//   13 : boss thon géant, COOPÉRATIF : le chat écrit dans le chat Twitch les mots affichés pour lui enlever de la vie
//   40 : piñata géante, COOPÉRATIVE : tout le monde tape dessus ; si le total de coups atteint
//        l'objectif avant la fin du temps, elle explose pour tous (objectif = nombre d'inscrits x 20)
// Compte à rebours, puis des objets traversent l'écran pendant ~25 s ; chaque viewer clique ce
// qu'il peut ; le plus de points gagne (égalité : le premier arrivé à ce score). Le serveur tire
// lui-même le calendrier des objets (type, valeur, heure, durée) et le publie : il peut donc
// vérifier chaque clic (objet existant à ce moment-là, compté une seule fois par viewer) sans
// qu'on puisse tricher en envoyant un score inventé.
// ===== Boss thon géant (numéro 13) : le chat doit écrire les mots affichés à l'écran pour lui faire perdre de la vie =====
// 3 mots sont affichés ; le PREMIER viewer qui écrit l'un d'eux dans le chat Twitch le « capture » : le boss perd 1 point de vie
// et un nouveau mot prend sa place. Si la vie tombe à 0 avant la fin du temps, le chat gagne (sinon le thon s'échappe).
// Classement = nombre de mots capturés ; 3/2/1 points mini-jeux seulement si le boss est vaincu.
const BOSS_MS = 60000;
const BOSS_SLOTS = 3;
const BOSS_HP_PER_PLAYER = Math.max(0.5, Math.min(10, parseFloat(process.env.BOSS_HP_PER_PLAYER) || 1.5)); // réglable sur Render
const BOSS_HP_MIN = 12; // pas de maximum : la vie suit le nombre d'inscrits
const BOSS_USER_COOLDOWN_MS = 350; // un même viewer ne peut pas capturer plus de ~3 mots/s
const BOSS_WORDS = [
  ["thon", "sushi", "algue", "perle", "ancre", "vague", "plage", "sable", "corail", "crabe", "nage", "banc", "mer"],
  ["sardine", "anchois", "requin", "dauphin", "baleine", "meduse", "pecheur", "harpon", "filet", "bateau", "pirate", "tresor", "hameçon", "tortue", "bingo", "numéro", "carton", "pastis"],
  ["aquarium", "crevette", "calamar", "maquereau", "saumon", "poisson", "hippocampe", "loterie", "gagnant", "carthon", "scaphandre", "tempête", "félicitations", "pêcheur"],
];
function bossNorm(t) { return String(t || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z]/g, ""); }
function bossPickWord(m) {
  const p = m.maxHp ? (m.maxHp - m.hp) / m.maxHp : 0;
  const tier = p < 0.34 ? 0 : p < 0.67 ? 1 : 2;
  const pool = [...BOSS_WORDS[tier], ...(tier > 0 ? BOSS_WORDS[tier - 1] : [])];
  const onScreen = new Set(m.words.map((w) => bossNorm(w.w)));
  let cands = pool.filter((w) => !onScreen.has(bossNorm(w)) && !m.used.has(w));
  if (cands.length === 0) { m.used.clear(); cands = pool.filter((w) => !onScreen.has(bossNorm(w))); }
  const w = cands[Math.floor(Math.random() * cands.length)];
  m.used.add(w);
  return { id: Math.random().toString(36).slice(2, 7), w };
}
// Appelée pour chaque message du chat. Renvoie true si le message a capturé un mot.
function handleBossChat(userId, pseudo, text) {
  const m = state.miniGame;
  if (!m || m.type !== "boss" || m.results || m.done || !userId) return false;
  const now = Date.now();
  if (now < m.ts || now > m.endsAt) return false;
  const norm = bossNorm(text);
  if (norm.length < 2) return false;
  const k = m.words.findIndex((w) => bossNorm(w.w) === norm);
  if (k < 0) return false;
  const u = m.users.get(userId) || { n: 0, pseudo: pseudo || null, last: 0, firstAt: now };
  if (now - u.last < BOSS_USER_COOLDOWN_MS) return false;
  u.n++; u.last = now; if (pseudo) u.pseudo = pseudo; m.users.set(userId, u);
  const word = m.words[k].w;
  m.hp = Math.max(0, m.hp - 1);
  m.feed.push({ pseudo: u.pseudo || "Un viewer", word, ts: now });
  if (m.feed.length > 5) m.feed.shift();
  if (m.hp <= 0) {
    m.done = true; m.doneAt = now; m.words = [];
    setTimeout(() => finalizeMiniGame(m).catch(() => {}), 2500);
  } else {
    m.words[k] = bossPickWord(m);
  }
  return true;
}
if (process.env.CARTHON_TEST_HOOKS) global.__bossChat = handleBossChat;

const MINIGAME_BY_NUMBER = { 13: "boss", 1: "voiture", 51: "pastis", 25: "peche", 40: "pinata", 69: "canard", 7: "puzzle", 33: "memoire", 75: "flappy" }; // Carthon Hero (simon) retiré du tirage à la demande du streamer ; le code reste en place
// Compte à rebours entre le tirage du numéro et le départ du mini-jeu. La vidéo Twitch arrive chez les viewers avec quelques
// secondes de retard (≈ 5 s) : leur overlay montre le numéro en retard, et le mini-jeu ne doit pas démarrer avant. 14 s laissent
// le temps de voir le numéro tomber et d'entendre l'annonce (retard vidéo jusqu'à ~9 s). Réglable avec la variable Render MG_START_DELAY_MS.
const MG_START_DELAY_MS = Math.max(3000, Math.min(30000, parseInt(process.env.MG_START_DELAY_MS, 10) || 14000));
const MG_SLACK_MS = 1500;       // tolérance réseau sur un clic
const MG_MAX_USERS = 3000;
const PINATA_MS = 32000;            // durée du jeu de rythme (la piñata se casse à coups de flèches)
const PINATA_FALL_MS = 1600;       // temps de chute d'une flèche (affichage client)
const PINATA_DMG_PER_PLAYER = Number(process.env.PINATA_DMG_PER_PLAYER) > 0 ? Number(process.env.PINATA_DMG_PER_PLAYER) : 25; // objectif = inscrits x 25 points...
const PINATA_MIN = 60, PINATA_MAX = 30000; // ...borné entre 60 et 30000
const PINATA_NOTES = 48;           // nombre de flèches dans la partition
// Partition déterministe : [temps en ms depuis le départ, voie 0..3 (gauche, bas, haut, droite)]. Rythme qui accélère.
function pinataChart(seed) {
  const rnd = mulberry32(seed >>> 0), notes = [];
  let t = 2200, last = -1;
  for (let i = 0; i < PINATA_NOTES; i++) {
    let lane = Math.floor(rnd() * 4);
    if (lane === last && rnd() < 0.6) lane = (lane + 1 + Math.floor(rnd() * 3)) % 4;
    notes.push([Math.round(t), lane]); last = lane;
    t += 660 - 280 * (i / PINATA_NOTES) + Math.floor(rnd() * 90);
  }
  return notes;
}
const DUCK_MS = 20000;          // durée de la chasse au canard
const DUCK_RADIUS = 6.5;        // rayon de touche (en % de la largeur de l'écran) : petit, le canard est difficile
const DUCK_T_SLACK_MS = 400;    // écart toléré entre l'heure annoncée par le client et l'heure serveur
const PUZZLE_MS = 60000;         // temps maximum pour finir le puzzle : au bout d'1 minute la partie s'arrête pour tout le monde
const PUZZLE_MIN_MS = 8000;     // en dessous, le temps est jugé impossible (20 pièces à placer) et refusé
const PUZZLE_GRACE_MS = 30000;  // après le premier arrivé, les autres ont encore 30 s
const MEM_PAIRS = 6;            // mémoire : 6 paires = 12 cartes
const MEM_MIN_MS = 5000;        // en dessous, temps jugé impossible
const FLAP_MS = 90000;           // durée maximale du jeu du poisson (nager entre les rochers)
const FLAP_MAX_EVENTS = 4000;    // nombre maximal de battements acceptés
const CAR_MS = 90000;           // durée maximale d'une course
const CAR_START_LIMIT_MS = 8000; // on peut encore prendre le départ jusqu'à 8 s après le signal
const CAR_MAX_EVENTS = 6000;     // nombre maximal de changements de touche acceptés
const SIMON_MS = 75000;         // durée de la partie
const SIMON_MAX = 40;           // longueur maximale de la suite
const SIMON_STEP_MS = 250;      // minimum humainement possible par pression (anti-script)
const pseudoCacheByUserId = new Map();

// Mémoire : même tirage de cartes pour tout le monde. Le viewer envoie la suite de cartes retournées ; le serveur
// rejoue la partie (paires, cartes déjà trouvées) pour vérifier que toutes les paires ont bien été trouvées.
function buildMemoryDeck() {
  const d = [];
  for (let i = 0; i < MEM_PAIRS; i++) d.push(i, i);
  for (let i = d.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [d[i], d[j]] = [d[j], d[i]]; }
  return d;
}
function memoryValid(m, flips) {
  const n = m.deck.length;
  if (!Array.isArray(flips) || flips.length < n || flips.length > 300 || flips.length % 2 !== 0) return false;
  const found = new Set();
  for (let i = 0; i < flips.length; i += 2) {
    const a = flips[i], b = flips[i + 1];
    if (!Number.isInteger(a) || !Number.isInteger(b) || a === b || a < 0 || b < 0 || a >= n || b >= n || found.has(a) || found.has(b)) return false;
    if (m.deck[a] === m.deck[b]) { found.add(a); found.add(b); }
  }
  return found.size === n;
}

// Trajectoire du canard : suite de points [décalage ms, x %, y %] reliés en ligne droite, vitesse 50 à 85 % de
// largeur d'écran par seconde, changement de direction toutes les ~0,4 à 0,9 s. Le serveur la publie, ce qui
// lui permet de vérifier chaque clic (position réelle du canard à l'instant du clic).
function buildDuckPath() {
  const pts = [[0, 20 + Math.random() * 60, 20 + Math.random() * 60]];
  let t = 0;
  while (t < DUCK_MS + 2000) {
    const [, px, py] = pts[pts.length - 1];
    let nx, ny, dist, tries = 0;
    do {
      nx = 6 + Math.random() * 88; ny = 10 + Math.random() * 78;
      dist = Math.hypot(nx - px, (ny - py) * 9 / 16);
      tries++;
    } while (dist < 22 && tries < 20);
    const speed = 75 + Math.random() * 45;
    t += Math.max(250, Math.round(dist / speed * 1000));
    pts.push([t, Math.round(nx * 10) / 10, Math.round(ny * 10) / 10]);
  }
  return pts;
}
function duckPosAt(path, off) {
  if (off <= 0) return [path[0][1], path[0][2]];
  for (let i = 1; i < path.length; i++) {
    if (off <= path[i][0]) {
      const a = path[i - 1], b = path[i], f = (off - a[0]) / (b[0] - a[0]);
      return [a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f];
    }
  }
  const l = path[path.length - 1];
  return [l[1], l[2]];
}

// o = départ (ms après le début), d = durée de traversée, v = points, y = hauteur (%), r = sens
function buildMiniGameItems(type) {
  const items = [];
  if (type === "peche") {
    let off = 0;
    while (off < 26000) {
      const r = Math.random();
      const kind = r < 0.12 ? "requin" : r < 0.20 ? "dore" : r < 0.38 ? "rouge" : "thon";
      const spec = { requin: [-3, 4800], dore: [5, 2800], rouge: [2, 4000], thon: [1, 5000] }[kind];
      items.push({ t: kind, v: spec[0], o: off, d: spec[1], y: Math.round(16 + Math.random() * 68), r: Math.random() < 0.5 ? 1 : -1 });
      off += 300 + Math.floor(Math.random() * 160);
    }
  } else {
    // Pluie dense et rapide : une bouteille toutes les ~0,3 s (irrégulier), chute de 1,7 à 2,3 s,
    // pendant ~26 s => environ 85 bouteilles. Il faut vraiment être rapide pour se démarquer.
    let off = 0;
    while (off < 26000) {
      // ~1 bouteille sur 6 (jamais au tout début) est une bouteille de cola : piège, la toucher élimine le joueur
      const coca = off > 2000 && Math.random() < 0.16;
      items.push({ t: coca ? "coca" : "bouteille", v: coca ? 0 : 1, o: off, d: 1700 + Math.floor(Math.random() * 600) });
      off += 220 + Math.floor(Math.random() * 160);
    }
  }
  return items;
}

function mgItemStart(m, k) { return m.ts + m.items[k].o; }
function mgEndsAt(m) { return m.ts + Math.max(...m.items.map((it) => it.o + it.d)) + MG_SLACK_MS; }

function startMiniGame(type) {
  const m = {
    id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
    type,
    ts: Date.now() + MG_START_DELAY_MS, // heure de départ
    items: type === "pinata" || type === "canard" || type === "puzzle" || type === "memoire" || type === "simon" || type === "voiture" || type === "flappy" || type === "boss" ? [] : buildMiniGameItems(type),
    scores: new Map(),                  // userId -> { set: Set(k), score, lastTs }
    results: null,                      // rempli à la fin
  };
  if (type === "pinata") {
    m.target = Math.max(PINATA_MIN, Math.min(PINATA_MAX, state.players.length * PINATA_DMG_PER_PLAYER));
    m.seed = Math.floor(Math.random() * 2147483647);
    m.notes = pinataChart(m.seed);
    m.clicks = 0;
    m.users = new Map(); // userId -> { n, last }
    m.done = false;      // passe à true à l'instant où l'objectif est atteint
    m.endsAt = m.ts + PINATA_MS + MG_SLACK_MS;
  } else if (type === "boss") {
    m.maxHp = Math.max(BOSS_HP_MIN, Math.round(state.players.length * BOSS_HP_PER_PLAYER));
    m.hp = m.maxHp;
    m.users = new Map(); // userId -> { n, pseudo, last, firstAt }
    m.used = new Set(); m.words = []; m.feed = []; m.done = false;
    for (let i = 0; i < BOSS_SLOTS; i++) m.words.push(bossPickWord(m));
    m.endsAt = m.ts + BOSS_MS + MG_SLACK_MS;
  } else if (type === "flappy") {
    m.seed = (Math.floor(Math.random() * 4294967295) + 1) >>> 0;
    m.hits = new Map(); // userId -> temps tenu (ms), calculé par le serveur en rejouant les battements
    m.endsAt = m.ts + FLAP_MS + CAR_START_LIMIT_MS + MG_SLACK_MS;
  } else if (type === "voiture") {
    m.seed = (Math.floor(Math.random() * 4294967295) + 1) >>> 0; // même parcours d'obstacles pour tout le monde
    m.hits = new Map(); // userId -> temps tenu (ms), calculé par le serveur en rejouant les touches
    m.endsAt = m.ts + CAR_MS + CAR_START_LIMIT_MS + MG_SLACK_MS;
  } else if (type === "simon") {
    // La suite complète reste secrète : le serveur ne donne à chaque joueur que le début dont il a besoin (une manche à la fois).
    m.seq = Array.from({ length: SIMON_MAX }, () => Math.floor(Math.random() * 4));
    m.endsAt = m.ts + SIMON_MS + MG_SLACK_MS;
  } else if (type === "memoire") {
    m.deck = buildMemoryDeck();
    m.hits = new Map();
    m.endsAt = m.ts + PUZZLE_MS + MG_SLACK_MS;
  } else if (type === "puzzle") {
    m.hits = new Map(); // userId -> temps mis (ms, mesuré par le serveur depuis le départ)
    m.endsAt = m.ts + PUZZLE_MS + MG_SLACK_MS;
  } else if (type === "canard") {
    m.path = buildDuckPath();
    m.hits = new Map();  // userId -> temps mis (ms) pour toucher le canard
    m.done = false;
    m.tries = new Map(); // userId -> heure du dernier essai raté
    m.endsAt = m.ts + DUCK_MS + MG_SLACK_MS;
  } else {
    m.endsAt = mgEndsAt(m);
  }
  state.miniGame = m;
  setTimeout(() => finalizeMiniGame(m).catch(() => {}), m.endsAt - Date.now() + 800);
}

function mgRanking(m) {
  return [...m.scores.entries()]
    .map(([userId, v]) => ({ userId, count: v.score, lastTs: v.lastTs }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count || a.lastTs - b.lastTs);
}

async function finalizeMiniGame(m) {
  if (m.results || state.miniGame !== m) return;
  if (m.type === "puzzle" || m.type === "memoire") {
    if (m.finalizing) return;
    m.finalizing = true;
    const top = [...m.hits.entries()].map(([userId, ms]) => ({ userId, ms })).sort((a, b) => a.ms - b.ms).slice(0, 3);
    const pseudos = await Promise.all(top.map((r) => pseudoForUserId(r.userId)));
    if (state.miniGame === m) { m.results = { top: top.map((r, i) => ({ pseudo: pseudos[i] || "Un viewer", ms: r.ms })), players: m.hits.size }; awardMiniPoints(top.map((r, i) => ({ userId: r.userId, pseudo: pseudos[i] }))); }
    return;
  }
  if (m.type === "boss") {
    if (m.finalizing) return;
    m.finalizing = true;
    const success = m.hp <= 0;
    const ranked = [...m.users.entries()].map(([userId, u]) => ({ userId, n: u.n, pseudo: u.pseudo, firstAt: u.firstAt })).sort((a, b) => b.n - a.n || a.firstAt - b.firstAt);
    const top = ranked.slice(0, 3);
    if (state.miniGame === m) {
      m.results = { success, hp: m.hp, maxHp: m.maxHp, words: ranked.reduce((a, r) => a + r.n, 0), top: top.map((r) => ({ pseudo: r.pseudo || "Un viewer", count: r.n })), players: ranked.length };
      if (success) awardMiniPoints(top.map((r) => ({ userId: r.userId, pseudo: r.pseudo })));
    }
    return;
  }
  if (m.type === "voiture" || m.type === "flappy") {
    if (m.finalizing) return;
    m.finalizing = true;
    const top = [...m.hits.entries()].map(([userId, ms]) => ({ userId, ms })).sort((a, b) => b.ms - a.ms).slice(0, 3); // le plus longtemps d'abord (égalité : le premier arrivé, ordre d'insertion conservé)
    const pseudos = await Promise.all(top.map((r) => pseudoForUserId(r.userId)));
    if (state.miniGame === m) { m.results = { top: top.map((r, i) => ({ pseudo: pseudos[i] || "Un viewer", ms: r.ms })), players: m.hits.size }; awardMiniPoints(top.map((r, i) => ({ userId: r.userId, pseudo: pseudos[i] }))); }
    return;
  }
  if (m.type === "canard") {
    if (m.finalizing) return;
    m.finalizing = true;
    const top = [...m.hits.entries()].map(([userId, ms]) => ({ userId, ms })).sort((a, b) => a.ms - b.ms).slice(0, 3);
    const pseudos = await Promise.all(top.map((r) => pseudoForUserId(r.userId)));
    if (state.miniGame === m) { m.results = { top: top.map((r, i) => ({ pseudo: pseudos[i] || "Un viewer", ms: r.ms })), players: m.hits.size }; awardMiniPoints(top.map((r, i) => ({ userId: r.userId, pseudo: pseudos[i] }))); }
    return;
  }
  if (m.type === "pinata") {
    if (m.finalizing) return;
    m.finalizing = true;
    const top = [...m.users.entries()].map(([userId, u]) => ({ userId, n: u.n })).sort((a, b) => b.n - a.n).slice(0, 3);
    const mvp = [];
    const pseudos = await Promise.all(top.map((r) => pseudoForUserId(r.userId)));
    top.forEach((r, i) => mvp.push({ pseudo: pseudos[i] || "Un viewer", count: r.n }));
    if (state.miniGame === m) { m.results = { success: m.clicks >= m.target, total: m.clicks, target: m.target, top: mvp }; if (m.clicks >= m.target) awardMiniPoints(top.map((r, i) => ({ userId: r.userId, pseudo: pseudos[i] }))); }
    return;
  }
  const top = mgRanking(m).slice(0, 3);
  const results = [], awards = [];
  for (const r of top) {
    const pseudo = await pseudoForUserId(r.userId);
    results.push({ pseudo: pseudo || "Un viewer", count: r.count });
    awards.push({ userId: r.userId, pseudo });
  }
  if (state.miniGame === m) { m.results = results; awardMiniPoints(awards); }
}

function publicMiniGame() {
  const m = state.miniGame;
  if (!m) return null;
  const out = { id: m.id, type: m.type, ts: m.ts, endsAt: m.endsAt, results: m.results };
  if (m.type === "pinata") { out.target = m.target; out.clicks = m.clicks; out.durationMs = PINATA_MS; out.done = !!m.done; out.notes = m.notes; out.fallMs = PINATA_FALL_MS; }
  else if (m.type === "simon") { out.durationMs = SIMON_MS; }
  else if (m.type === "voiture") { out.durationMs = CAR_MS; out.seed = m.seed; }
  else if (m.type === "flappy") { out.durationMs = FLAP_MS; out.seed = m.seed; }
  else if (m.type === "boss") {
    out.durationMs = BOSS_MS; out.hp = m.hp; out.maxHp = m.maxHp; out.done = !!m.done; out.chatOk = chatBotConnected;
    out.words = Date.now() >= m.ts && !m.done && !m.results ? m.words.map((w) => ({ id: w.id, w: w.w })) : []; // les mots ne sont publiés qu'au départ
    out.feed = m.feed.slice(-4);
    out.top = [...m.users.values()].sort((a, b) => b.n - a.n || a.firstAt - b.firstAt).slice(0, 3).map((u) => ({ pseudo: u.pseudo || "Un viewer", count: u.n }));
  }
  else if (m.type === "puzzle") { out.durationMs = PUZZLE_MS; }
  else if (m.type === "memoire") { out.durationMs = PUZZLE_MS; out.deck = m.deck; }
  else if (m.type === "canard") { out.durationMs = DUCK_MS; if (Date.now() < m.endsAt) out.path = m.path; }
  else if (Date.now() < m.endsAt) out.items = m.items; // le calendrier n'est utile que pendant le jeu
  return out;
}

async function pseudoForUserId(userId) {
  if (pseudoByUserId[userId]) return pseudoByUserId[userId];
  if (pseudoCacheByUserId.has(userId)) return pseudoCacheByUserId.get(userId);
  if (!/^\d+$/.test(String(userId))) return null;
  try {
    const token = await getAppAccessToken();
    const r = await fetch("https://api.twitch.tv/helix/users?id=" + userId, {
      headers: { "Client-Id": TWITCH_CLIENT_ID, Authorization: "Bearer " + token },
    });
    const data = await r.json();
    const user = data.data && data.data[0];
    if (!user) return null;
    const pseudo = cleanPseudo(user.display_name);
    if (pseudoCacheByUserId.size > 5000) pseudoCacheByUserId.clear();
    pseudoCacheByUserId.set(userId, pseudo);
    return pseudo;
  } catch (e) { return null; }
}

// Un viewer envoie la liste des bouteilles qu'il a éclatées (numéros de bouteille). Il faut avoir
// partagé son identité Twitch (le jeton le prouve). Seules comptent les bouteilles qui existaient
// vraiment à cet instant, une seule fois chacune.
app.post("/minigame-hit", rateLimit("minigame", 240, 60000), (req, res) => {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const payload = verifyTwitchExtensionToken(token);
  if (!payload) return res.status(401).json({ error: "token invalide" });
  if (!payload.user_id) return res.json({ ok: true, score: 0, reason: "no_identity" });
  const m = state.miniGame;
  if (!m || String(req.body && req.body.id) !== m.id) return res.json({ ok: true, score: 0, reason: "expired" });
  const now = Date.now();
  if (m.type === "boss") return res.json({ ok: true, score: 0, reason: "chat_only" }); // ce jeu se joue dans le chat Twitch
  if (m.type === "pinata") {
    // Piñata : le viewer envoie "n coups depuis le dernier envoi". On borne n par la cadence humaine
    // (10 coups/s) pour qu'un script ne fasse pas exploser la piñata à lui tout seul.
    if (m.done || m.results) return res.json({ ok: true, total: m.clicks, done: true, reason: "done" });
    if (now < m.ts - MG_SLACK_MS || now > m.ts + PINATA_MS + MG_SLACK_MS) return res.json({ ok: true, total: m.clicks, reason: "expired" });
    let u = m.users.get(payload.user_id);
    if (!u) {
      if (m.users.size >= MG_MAX_USERS) return res.json({ ok: true, total: m.clicks, reason: "full" });
      u = { n: 0, last: m.ts };
      m.users.set(payload.user_id, u);
    }
    const n = Math.floor(Number(req.body && req.body.n));
    // Plafond : 2 points (Parfait) par flèche déjà tombée à portée (+ marge), jamais plus => un script
    // qui envoie n'importe quoi ne dépasse pas ce qu'un joueur parfait pourrait marquer.
    const el = now - m.ts + MG_SLACK_MS;
    let due = 0; for (const nt of m.notes) if (nt[0] <= el) due++;
    const allowed = Math.max(0, due * 2 - u.n);
    const add = Number.isFinite(n) && n > 0 ? Math.min(n, allowed, 100) : 0;
    u.last = Math.max(u.last, now);
    u.n += add; m.clicks += add;
    if (m.clicks >= m.target) {
      // Objectif atteint : on l'annonce IMMÉDIATEMENT (drapeau "done" publié dans /state et renvoyé
      // à ce viewer) ; les pseudos des meilleurs frappeurs sont cherchés ensuite, sans retarder l'explosion.
      m.done = true;
      finalizeMiniGame(m).catch(() => {});
    }
    return res.json({ ok: true, total: m.clicks, done: !!m.done });
  }
  if (m.type === "simon") {
    // Le viewer envoie ce qu'il a reproduit ; [] = il démarre. Manche n = suite de n couleurs. Faux = éliminé.
    if (m.results) return res.json({ ok: true, expired: true });
    if (now < m.ts - 500 || now > m.endsAt) return res.json({ ok: true, expired: true });
    let e = m.scores.get(payload.user_id);
    if (!e) {
      if (m.scores.size >= MG_MAX_USERS) return res.json({ ok: true, reason: "full" });
      e = { set: new Set(), score: 0, lastTs: 0, dead: false, started: false, roundStart: 0 };
      m.scores.set(payload.user_id, e);
    }
    if (e.dead) return res.json({ ok: true, dead: true, score: e.score });
    const input = req.body && req.body.input;
    if (!Array.isArray(input) || input.length > SIMON_MAX + 1 || !input.every((x) => Number.isInteger(x) && x >= 0 && x < 4)) return res.json({ ok: true, reason: "invalid", score: e.score, seq: e.started ? m.seq.slice(0, e.score + 1) : undefined });
    if (input.length === 0) { // démarrage (ou reprise après une coupure réseau) : on renvoie la suite de la manche en cours
      if (!e.started) { e.started = true; e.roundStart = now; }
      return res.json({ ok: true, score: e.score, seq: m.seq.slice(0, e.score + 1) });
    }
    const need = e.score + 1;
    if (input.length !== need) return res.json({ ok: true, reason: "invalid", score: e.score, seq: m.seq.slice(0, need) });
    if (now - e.roundStart < need * SIMON_STEP_MS) return res.json({ ok: true, reason: "too_fast", score: e.score, seq: m.seq.slice(0, need) });
    if (input.every((x, i) => x === m.seq[i])) {
      e.score++; e.lastTs = now; e.roundStart = now;
      if (e.score >= SIMON_MAX) { e.dead = true; return res.json({ ok: true, correct: true, score: e.score, finished: true }); }
      return res.json({ ok: true, correct: true, score: e.score, seq: m.seq.slice(0, e.score + 1) });
    }
    e.dead = true;
    return res.json({ ok: true, correct: false, dead: true, score: e.score });
  }
  if (m.type === "flappy") {
    // Le viewer envoie les ticks où il a donné un coup de nageoire ; le serveur REJOUE la partie (même moteur que le client)
    // et en tire le temps tenu : impossible d'envoyer un faux temps. Une seule partie par joueur.
    if (m.results) return res.json({ ok: true, done: false, reason: "expired" });
    if (m.hits.has(payload.user_id)) return res.json({ ok: true, done: true, already: true, ms: m.hits.get(payload.user_id) });
    if (now < m.ts - 500 || now > m.endsAt) return res.json({ ok: true, done: false, reason: "expired" });
    const fl = req.body && req.body.flaps;
    if (!Array.isArray(fl) || fl.length > FLAP_MAX_EVENTS) return res.json({ ok: true, done: false, reason: "invalid" });
    let prev = -99;
    for (const t of fl) {
      if (!Number.isInteger(t) || t < 0 || t > FL_MAX_TICKS || t - prev < 3) return res.json({ ok: true, done: false, reason: "invalid" }); // au plus ~20 battements/s
      prev = t;
    }
    const ticks = flapReplay(m.seed, fl);
    const ms = Math.round((ticks * 1000) / FL_TPS);
    if (ms > now - m.ts + 1500) return res.json({ ok: true, done: false, reason: "too_fast" });
    if (m.hits.size >= MG_MAX_USERS) return res.json({ ok: true, done: false, reason: "full" });
    m.hits.set(payload.user_id, ms);
    return res.json({ ok: true, done: true, ms });
  }
  if (m.type === "voiture") {
    // Le viewer envoie la liste de ses changements de direction ; le serveur REJOUE la course (même moteur que le client)
    // et en tire le temps tenu : impossible d'envoyer un faux temps. Une seule course par joueur.
    if (m.results) return res.json({ ok: true, done: false, reason: "expired" });
    if (m.hits.has(payload.user_id)) return res.json({ ok: true, done: true, already: true, ms: m.hits.get(payload.user_id) });
    if (now < m.ts - 500 || now > m.endsAt) return res.json({ ok: true, done: false, reason: "expired" });
    const ev = req.body && req.body.events;
    if (!Array.isArray(ev) || ev.length > CAR_MAX_EVENTS) return res.json({ ok: true, done: false, reason: "invalid" });
    let prev = -1;
    for (const e of ev) {
      if (!Array.isArray(e) || e.length !== 2 || !Number.isInteger(e[0]) || !Number.isInteger(e[1]) || e[0] < prev || e[0] < 0 || e[0] > CAR_MAX_TICKS || e[1] < 0 || e[1] > 8) return res.json({ ok: true, done: false, reason: "invalid" });
      prev = e[0];
    }
    const ticks = carReplay(m.seed, ev);
    const ms = Math.round((ticks * 1000) / CAR_TPS);
    // On ne peut pas avoir tenu plus longtemps que le temps réellement écoulé depuis le départ de la course.
    if (ms > now - m.ts + 1500) return res.json({ ok: true, done: false, reason: "too_fast" });
    if (m.hits.size >= MG_MAX_USERS) return res.json({ ok: true, done: false, reason: "full" });
    m.hits.set(payload.user_id, ms);
    return res.json({ ok: true, done: true, ms });
  }
  if (m.type === "puzzle" || m.type === "memoire") {
    // Le viewer annonce qu'il a fini ; le temps est mesuré par le serveur (pas de temps envoyé par le client).
    if (m.results) return res.json({ ok: true, done: false, reason: "expired" });
    if (m.hits.has(payload.user_id)) return res.json({ ok: true, done: true, already: true, ms: m.hits.get(payload.user_id) });
    if (now > m.endsAt) return res.json({ ok: true, done: false, reason: "expired" });
    const ms = now - m.ts;
    if (m.type === "memoire") {
      if (ms < MEM_MIN_MS) return res.json({ ok: true, done: false, reason: "too_fast" });
      if (!memoryValid(m, req.body && req.body.flips)) return res.json({ ok: true, done: false, reason: "invalid" });
    } else if (ms < PUZZLE_MIN_MS) return res.json({ ok: true, done: false, reason: "too_fast" });
    if (m.hits.size >= MG_MAX_USERS) return res.json({ ok: true, done: false, reason: "full" });
    m.hits.set(payload.user_id, ms);
    if (m.hits.size === 1) { // premier arrivé : plus que 30 s pour les autres
      m.endsAt = Math.min(m.endsAt, now + PUZZLE_GRACE_MS);
      setTimeout(() => finalizeMiniGame(m).catch(() => {}), PUZZLE_GRACE_MS + 800);
    }
    return res.json({ ok: true, done: true, ms });
  }
  if (m.type === "canard") {
    // Le viewer annonce où et quand il a cliqué (x, y en % de l'écran, t = heure serveur estimée).
    // Chacun peut toucher le canard une fois ; le classement se fait au temps mis depuis le départ.
    if (m.results) return res.json({ ok: true, hit: false, reason: "expired" });
    if (m.hits.has(payload.user_id)) return res.json({ ok: true, hit: false, already: true, ms: m.hits.get(payload.user_id) });
    if (now < m.ts || now > m.ts + DUCK_MS + MG_SLACK_MS) return res.json({ ok: true, hit: false, reason: "expired" });
    const last = m.tries.get(payload.user_id) || 0;
    if (now - last < 120) return res.json({ ok: true, hit: false, reason: "slow_down" });
    const x = Number(req.body.x), y = Number(req.body.y);
    let t = Number(req.body.t);
    if (![x, y, t].every(Number.isFinite)) return res.json({ ok: true, hit: false });
    t = Math.max(now - DUCK_T_SLACK_MS - 400, Math.min(now, t));
    // le clic doit être sur le canard à l'heure annoncée (ou à l'heure serveur, petite marge réseau)
    let ok = false;
    for (const tt of [t, now - 100, now]) {
      const [cx, cy] = duckPosAt(m.path, tt - m.ts);
      if (Math.hypot(x - cx, (y - cy) * 9 / 16) <= DUCK_RADIUS) { ok = true; break; }
    }
    if (!ok) {
      if (m.tries.size < MG_MAX_USERS) m.tries.set(payload.user_id, now);
      return res.json({ ok: true, hit: false });
    }
    if (m.hits.size >= MG_MAX_USERS) return res.json({ ok: true, hit: false, reason: "full" });
    const ms = Math.max(0, Math.round(t - m.ts));
    m.hits.set(payload.user_id, ms);
    return res.json({ ok: true, hit: true, ms });
  }
  const list = Array.isArray(req.body.bottles) ? req.body.bottles.slice(0, 80) : [];
  let entry = m.scores.get(payload.user_id);
  if (!entry) {
    if (m.scores.size >= MG_MAX_USERS) return res.json({ ok: true, score: 0, reason: "full" });
    entry = { set: new Set(), score: 0, lastTs: 0, dead: false };
    m.scores.set(payload.user_id, entry);
  }
  for (const k of list) {
    if (entry.dead) break; // éliminé par une bouteille de cola : plus rien ne compte pour lui
    if (!Number.isInteger(k) || k < 0 || k >= m.items.length || entry.set.has(k)) continue;
    const it = m.items[k];
    const start = mgItemStart(m, k);
    if (now < start - MG_SLACK_MS || now > start + it.d + MG_SLACK_MS) continue;
    entry.set.add(k);
    if (it.t === "coca") { entry.dead = true; continue; }
    entry.score += it.v;
    entry.lastTs = now;
  }
  res.json({ ok: true, score: entry.score });
});

app.post("/start-wheel-spin", (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { names } = req.body || {};
  if (!Array.isArray(names) || names.length < 2 || names.length > 60 || !names.every((n) => typeof n === "string" && n.length > 0 && n.length <= 80)) {
    return res.status(400).json({ error: "il faut entre 2 et 60 pseudos valides" });
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
let chatBotConnected = false;

if (BOT_USERNAME && BOT_OAUTH_TOKEN && CHANNEL_NAME) {
  const client = new tmi.Client({
    identity: { username: BOT_USERNAME, password: BOT_OAUTH_TOKEN },
    channels: [CHANNEL_NAME],
  });

  client.connect().catch((err) => console.log("Erreur de connexion au chat :", err));

  client.on("connected", () => {
    chatBotConnected = true;
    console.log("Bot de chat connecté sur #" + CHANNEL_NAME);
  });
  client.on("disconnected", () => { chatBotConnected = false; });

  client.on("message", (channel, tags, message, self) => {
    if (self) return;
    // Boss thon géant : chaque message du chat est comparé aux mots affichés à l'écran.
    if (state.miniGame && state.miniGame.type === "boss") {
      try { handleBossChat(tags["user-id"], cleanPseudo(tags["display-name"] || tags.username), message); } catch (e) {}
    }
    const text = message.trim().toLowerCase();
    if (text === "!carthon") {
      const pseudo = cleanPseudo(tags["display-name"] || tags.username);
      if (!pseudo) return;
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


// ---------- Sauvegarde de la partie en cours ----------
function gameSnapshot() {
  return {
    drawn: state.drawn, players: state.players, tierWinners: state.tierWinners, winner: state.winner,
    pendingFinalists: state.pendingFinalists, pendingFinalistsDrawCount: state.pendingFinalistsDrawCount,
    started: state.started, gameId: state.gameId, registrationEndsAt: state.registrationEndsAt,
    miniPoints: state.miniPoints, miniBonus: state.miniBonus,
  };
}
function restoreGameSnapshot(v) {
  if (!v || typeof v !== "object" || !Array.isArray(v.drawn) || !Array.isArray(v.players) || typeof v.gameId !== "string") return;
  state = {
    ...state,
    drawn: v.drawn.filter((n) => Number.isInteger(n)),
    players: v.players.filter((p) => p && typeof p.pseudo === "string").map((p) => ({ pseudo: p.pseudo, isSub: !!p.isSub, hasBonus: !!p.hasBonus })),
    miniPoints: v.miniPoints && typeof v.miniPoints === "object" ? v.miniPoints : {},
    miniBonus: v.miniBonus && typeof v.miniBonus.pseudo === "string" ? v.miniBonus : null,
    tierWinners: v.tierWinners && typeof v.tierWinners === "object" ? v.tierWinners : { 1: null, 2: null, 3: null },
    winner: v.winner || null,
    pendingFinalists: Array.isArray(v.pendingFinalists) ? v.pendingFinalists : [],
    pendingFinalistsDrawCount: v.pendingFinalistsDrawCount == null ? null : v.pendingFinalistsDrawCount,
    started: !!v.started,
    gameId: v.gameId,
    registrationEndsAt: typeof v.registrationEndsAt === "number" ? v.registrationEndsAt : null,
  };
  console.log("Partie en cours restaurée depuis Redis : " + state.players.length + " inscrits, " + state.drawn.length + " numéros tirés.");
}
let lastSnapshotJson = null;
function saveGameSnapshotIfChanged() {
  if (!dataReady || redisUnreadable.has("gameSnapshot")) return;
  const json = JSON.stringify(gameSnapshot());
  if (json === lastSnapshotJson) return;
  lastSnapshotJson = json;
  redisSetJSON("gameSnapshot", gameSnapshot());
}

// Données à ne JAMAIS perdre : clé Redis -> [lecteur, écriture en mémoire, valeur par défaut]
const PERSISTED = {
  unlockedFramesByPseudo: [() => unlockedFramesByPseudo, (v) => { unlockedFramesByPseudo = v; }, {}],
  displayChoiceByPseudo: [() => displayChoiceByPseudo, (v) => { displayChoiceByPseudo = v; }, {}],
  winsByPseudo: [() => winsByPseudo, (v) => { winsByPseudo = v; }, {}],
  gamesByPseudo: [() => gamesByPseudo, (v) => { gamesByPseudo = v; }, {}],
  pseudoByUserId: [() => pseudoByUserId, (v) => { pseudoByUserId = v; }, {}],
  overlayVisible: [() => overlayVisible, (v) => { overlayVisible = v; }, true],
  overlayDelayMs: [() => overlayDelayMs, (v) => { overlayDelayMs = (typeof v === "number" && v >= 0 && v <= 20000) ? v : 0; }, 0],
  overlayVolume: [() => overlayVolume, (v) => { overlayVolume = (typeof v === "number" && v >= 0 && v <= 1) ? v : 1; }, 1],
  lastWinner: [() => lastWinner, (v) => { lastWinner = v; }, null],
  // Partie en cours (inscrits, numéros tirés, gagnants...) : sans ça, un redémarrage du serveur
  // (redéploiement, plantage) effaçait la partie et les joueurs perdaient leur carton.
  gameSnapshot: [gameSnapshot, restoreGameSnapshot, null],
};

// Copie de sauvegarde datée (une par jour et par clé, jamais écrasée) : si un jour une erreur
// abîme les données, on peut retrouver l'état de la veille dans la console Upstash
// (clés "backup:AAAA-MM-JJ:nomdelaclé").
async function dailyBackup() {
  if (!REDIS_ENABLED || !dataReady) return;
  const day = new Date().toISOString().slice(0, 10);
  for (const key of Object.keys(PERSISTED)) {
    if (redisUnreadable.has(key)) continue;
    const bkey = "backup:" + day + ":" + key;
    const existing = await redisGetJSON(bkey, undefined, 2);
    if (redisUnreadable.has(bkey)) { redisUnreadable.delete(bkey); continue; } // lecture en erreur : on ne risque pas d'écraser
    if (existing !== undefined) continue; // la sauvegarde du jour existe déjà
    const value = PERSISTED[key][0]();
    if (value === null || (typeof value === "object" && Object.keys(value).length === 0)) continue;
    await redisSetJSON(bkey, value);
  }
}

// Si une clé était illisible au démarrage, on réessaie régulièrement ; dès qu'elle revient,
// on fusionne : les données de Redis servent de base, les changements faits entre-temps en
// mémoire (pseudo par pseudo) gardent la priorité.
async function retryUnreadableKeys() {
  for (const key of [...redisUnreadable]) {
    if (!PERSISTED[key]) continue;
    const loaded = await redisGetJSON(key, undefined, 2);
    if (loaded === undefined || redisUnreadable.has(key)) continue;
    const [get, set] = PERSISTED[key];
    const mem = get();
    set(typeof loaded === "object" && loaded !== null && typeof mem === "object" && mem !== null ? { ...loaded, ...mem } : loaded);
    console.log("Redis : clé " + key + " enfin relue, données fusionnées.");
    await redisSetJSON(key, get());
  }
}

(async () => {
  for (const key of Object.keys(PERSISTED)) {
    const [, set, fallback] = PERSISTED[key];
    set(await redisGetJSON(key, fallback, 5));
  }
  dataReady = true;
  if (redisUnreadable.size > 0) {
    console.error("⚠️ ATTENTION : clés Redis illisibles au démarrage (" + [...redisUnreadable].join(", ") + ") — elles ne seront PAS écrasées ; nouvelle tentative toutes les 30 s.");
  }
  lastSnapshotJson = JSON.stringify(gameSnapshot());
  setInterval(saveGameSnapshotIfChanged, 1500);
  setInterval(retryUnreadableKeys, 30000);
  dailyBackup().catch(() => {});
  setInterval(() => dailyBackup().catch(() => {}), 6 * 3600 * 1000);
  console.log(
    REDIS_ENABLED
      ? "Stockage persistant Redis connecté — cadres/badges/titres restaurés."
      : "⚠️ Redis non configuré (UPSTASH_REDIS_REST_URL/TOKEN manquants) — les cadres/badges/titres ne survivront PAS à un redémarrage."
  );

  // Résout l'ID de NOTRE chaîne avant d'accepter des requêtes (garde-fou de chaîne)
  await resolveAllowedChannel();

  // Redéploiement Render = signal d'arrêt : on laisse les écritures Redis en cours se terminer.
  process.on("SIGTERM", async () => {
    try { saveGameSnapshotIfChanged(); } catch (e) {}
    for (let i = 0; i < 40 && [...writeState.values()].some((s) => s.running || s.dirty); i++) await sleep(100);
    process.exit(0);
  });

  // Dernier filet : une erreur imprévue ne doit jamais révéler de détails internes.
  app.use((err, req, res, next) => {
    console.error("Erreur non gérée :", err && err.message);
    if (res.headersSent) return next(err);
    res.status(err && err.status === 400 ? 400 : 500).json({ error: "erreur serveur" });
  });

  app.listen(PORT, () => {
    console.log("Serveur démarré sur le port " + PORT);
  });
})();
