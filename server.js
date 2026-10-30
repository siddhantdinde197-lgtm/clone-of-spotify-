/* ==========================================================
   Musify – backend (Node.js + Express)
   - JWT auth (register / login)
   - Track library + MP3 uploads (multer)
   - Likes and playlists per user
   - Data stored in data/db.json (no database install needed)
   ========================================================== */
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-before-deploying";

const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const DB_FILE = path.join(DATA_DIR, "db.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------------- Tiny JSON database ---------------- */
const DEMO_BASE = "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-";
function seed() {
  const demo = [
    ["Midnight Drive", "Nova Lane", "Neon Streets"],
    ["Paper Planes", "The Wanderers", "Slow Mornings"],
    ["Golden Hour", "Aria Bloom", "Sunday Light"],
    ["Glass Harbor", "Kite & Co.", "Tidelines"],
    ["Static Dreams", "Nova Lane", "Neon Streets"],
    ["Rooftop Rain", "Aria Bloom", "Sunday Light"],
    ["Feel the Echo", "The Wanderers", "Slow Mornings"],
    ["Afterglow", "Kite & Co.", "Tidelines"]
  ];
  return {
    users: [],
    likes: {},        // userId -> [trackId]
    playlists: [],    // { id, userId, name, trackIds: [] }
    tracks: demo.map(([title, artist, album], i) => ({
      id: "demo-" + (i + 1),
      title, artist, album,
      src: DEMO_BASE + (i + 1) + ".mp3",
      ownerId: null,
      createdAt: Date.now() + i
    }))
  };
}

let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, "utf8")) : seed();
function save() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
save();

/* ---------------- App setup ---------------- */
const app = express();
app.use(express.json({ limit: "100kb" }));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, "public")));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || ".mp3";
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("audio/")) cb(null, true);
    else cb(new Error("Only audio files are allowed."));
  }
});

/* ---------------- Auth helpers ---------------- */
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in first." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === payload.id);
    if (!user) return res.status(401).json({ error: "Account not found." });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Your session expired. Please log in again." });
  }
}
const publicUser = u => ({ id: u.id, username: u.username });
const makeToken = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "7d" });
const clean = (s, max) => String(s || "").trim().slice(0, max);

/* ---------------- Auth routes ---------------- */
app.post("/api/auth/register", async (req, res) => {
  const username = clean(req.body.username, 24);
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username))
    return res.status(400).json({ error: "Username must be 3–24 letters, numbers or underscores." });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: "That username is taken." });

  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash: await bcrypt.hash(password, 10),
    createdAt: Date.now()
  };
  db.users.push(user);
  db.likes[user.id] = [];
  save();
  res.status(201).json({ token: makeToken(user), user: publicUser(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const username = clean(req.body.username, 24);
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Wrong username or password." });
  res.json({ token: makeToken(user), user: publicUser(user) });
});

app.get("/api/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

/* ---------------- Track routes ---------------- */
app.get("/api/tracks", (req, res) => {
  const q = clean(req.query.q, 100).toLowerCase();
  let list = db.tracks;
  if (q) {
    list = list.filter(t =>
      t.title.toLowerCase().includes(q) ||
      t.artist.toLowerCase().includes(q) ||
      t.album.toLowerCase().includes(q));
  }
  res.json(list);
});

app.post("/api/tracks", auth, upload.single("audio"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Choose an audio file to upload." });
  const track = {
    id: crypto.randomUUID(),
    title: clean(req.body.title, 80) || path.parse(req.file.originalname).name,
    artist: clean(req.body.artist, 60) || "Unknown artist",
    album: clean(req.body.album, 60) || "Single",
    src: "/uploads/" + req.file.filename,
    file: req.file.filename,
    ownerId: req.user.id,
    createdAt: Date.now()
  };
  db.tracks.push(track);
  save();
  res.status(201).json(track);
});

app.delete("/api/tracks/:id", auth, (req, res) => {
  const track = db.tracks.find(t => t.id === req.params.id);
  if (!track) return res.status(404).json({ error: "Track not found." });
  if (track.ownerId !== req.user.id) return res.status(403).json({ error: "You can only delete your own uploads." });

  db.tracks = db.tracks.filter(t => t.id !== track.id);
  Object.keys(db.likes).forEach(uid => { db.likes[uid] = db.likes[uid].filter(id => id !== track.id); });
  db.playlists.forEach(p => { p.trackIds = p.trackIds.filter(id => id !== track.id); });
  if (track.file) fs.unlink(path.join(UPLOAD_DIR, track.file), () => {});
  save();
  res.json({ ok: true });
});

/* ---------------- Likes ---------------- */
app.get("/api/likes", auth, (req, res) => res.json(db.likes[req.user.id] || []));

app.post("/api/likes/:trackId", auth, (req, res) => {
  if (!db.tracks.some(t => t.id === req.params.trackId))
    return res.status(404).json({ error: "Track not found." });
  const list = db.likes[req.user.id] || (db.likes[req.user.id] = []);
  const i = list.indexOf(req.params.trackId);
  if (i === -1) list.push(req.params.trackId);
  else list.splice(i, 1);
  save();
  res.json({ liked: i === -1, likes: list });
});

/* ---------------- Playlists ---------------- */
const mine = req => db.playlists.filter(p => p.userId === req.user.id);
const findMine = req => db.playlists.find(p => p.id === req.params.id && p.userId === req.user.id);

app.get("/api/playlists", auth, (req, res) => res.json(mine(req)));

app.post("/api/playlists", auth, (req, res) => {
  const name = clean(req.body.name, 40);
  if (!name) return res.status(400).json({ error: "Give your playlist a name." });
  const playlist = { id: crypto.randomUUID(), userId: req.user.id, name, trackIds: [] };
  db.playlists.push(playlist);
  save();
  res.status(201).json(playlist);
});

app.delete("/api/playlists/:id", auth, (req, res) => {
  const p = findMine(req);
  if (!p) return res.status(404).json({ error: "Playlist not found." });
  db.playlists = db.playlists.filter(x => x.id !== p.id);
  save();
  res.json({ ok: true });
});

app.post("/api/playlists/:id/tracks", auth, (req, res) => {
  const p = findMine(req);
  if (!p) return res.status(404).json({ error: "Playlist not found." });
  const trackId = String(req.body.trackId || "");
  if (!db.tracks.some(t => t.id === trackId)) return res.status(404).json({ error: "Track not found." });
  if (!p.trackIds.includes(trackId)) p.trackIds.push(trackId);
  save();
  res.json(p);
});

app.delete("/api/playlists/:id/tracks/:trackId", auth, (req, res) => {
  const p = findMine(req);
  if (!p) return res.status(404).json({ error: "Playlist not found." });
  p.trackIds = p.trackIds.filter(id => id !== req.params.trackId);
  save();
  res.json(p);
});

/* ---------------- Errors ---------------- */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE")
    return res.status(413).json({ error: "File is too large (25 MB max)." });
  console.error(err);
  res.status(400).json({ error: err.message || "Something went wrong." });
});

app.listen(PORT, () => console.log(`Musify running at http://localhost:${PORT}`));
