"""
==============================================================
  OSINT Face Finder - Maximum Efficiency Edition
  Findet Personen anhand eines Ziel-Fotos mit KI
==============================================================
  Modi:
    1. Analyse-Modus:    python app.py --analyze bild.jpg
    2. Such-Modus:       python app.py --target oma.jpg --scan ordner/
    3. Vergleichs-Modus: python app.py --target oma.jpg --compare bild2.jpg
    4. Username-Suche:   python app.py --username max_mustermann
    5. Social von Foto:  python app.py --social schwester.jpg
==============================================================
"""

import cv2
import os
import sys
import json
import argparse
import time
import re
import webbrowser
import urllib.parse
import urllib.request
import concurrent.futures
import threading
import numpy as np
from pathlib import Path
from datetime import datetime

try:
    import requests as _req
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# ─── Abhängigkeiten prüfen ────────────────────────────────────────────────────
def check_deps():
    missing = []
    try:
        import insightface
    except ImportError:
        missing.append("insightface")
    try:
        import onnxruntime
    except ImportError:
        missing.append("onnxruntime-gpu  # oder onnxruntime")
    if missing:
        print("[-] Fehlende Pakete:", ", ".join(missing))
        print("    Installiere mit: pip install " + " ".join(missing))
        sys.exit(1)

check_deps()

if not _REQUESTS_OK:
    warn_once = lambda: print(f"{C.YELLOW}[!]{C.RESET} 'requests' fehlt – Username-Suche eingeschränkt. "
                              "Installiere mit: pip install requests")
else:
    warn_once = lambda: None

from insightface.app import FaceAnalysis
from insightface.utils import face_align

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM-DATENBANK
# Felder:
#   url      = Profil-URL (wird auch als Ergebnis-Link angezeigt)
#   api      = (optional) bessere Check-URL (API-Endpunkt, zuverlässiger)
#   err      = Substring der NUR auf Fehlerseiten vorkommt
#   code     = HTTP-Code wenn Account NICHT existiert (default: 404)
#   ok       = Substring der NUR bei existierendem Account vorkommt
#   reliable = True → Ergebnis zuverlässig (API/err-String)
#              False → nur Code-Check, möglicher False-Positive
# ─────────────────────────────────────────────────────────────────────────────
PLATFORMS: dict = {
    # ── Mainstream ──────────────────────────────────────────────────────────
    "Instagram":    {"url":  "https://www.instagram.com/{}/",
                     "api":  "https://www.instagram.com/{}/?__a=1&__d=dis",
                     "err":  "Sorry, this page",
                     "reliable": True},
    "TikTok":       {"url":  "https://www.tiktok.com/@{}",
                     # oEmbed: 200+JSON=existiert, 400/404=nicht gefunden
                     "api":  "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{}",
                     "ok":   "author_name",
                     "reliable": True},
    "Twitter/X":    {"url":  "https://x.com/{}",
                     "err":  "This account doesn",
                     "reliable": True},
    "YouTube":      {"url":  "https://www.youtube.com/@{}",
                     "err":  "This page isn",
                     "reliable": True},
    "Facebook":     {"url":  "https://www.facebook.com/{}",
                     "code": 404,
                     "reliable": False},
    "Pinterest":    {"url":  "https://www.pinterest.com/{}/",
                     "err":  "isn't available",
                     "reliable": True},
    "Snapchat":     {"url":  "https://www.snapchat.com/add/{}",
                     "err":  "Sorry! We couldn",
                     "reliable": True},
    "Reddit":       {"url":  "https://www.reddit.com/user/{}",
                     "api":  "https://www.reddit.com/user/{}/about.json",
                     "ok":   "\"name\":",
                     "reliable": True},
    "LinkedIn":     {"url":  "https://www.linkedin.com/in/{}",
                     "code": 404,
                     "reliable": False},
    "Twitch":       {"url":  "https://www.twitch.tv/{}",
                     "api":  "https://api.twitch.tv/helix/users?login={}",
                     "err":  "Sorry. Unless you",
                     "reliable": True},
    "BeReal":       {"url":  "https://bere.al/{}",
                     "code": 404,
                     "reliable": False},
    "Tumblr":       {"url":  "https://{}.tumblr.com/",
                     "err":  "There's nothing here",
                     "reliable": True},
    "Flickr":       {"url":  "https://www.flickr.com/people/{}/",
                     "code": 404,
                     "reliable": False},
    "SoundCloud":   {"url":  "https://soundcloud.com/{}",
                     "code": 404,
                     "reliable": False},
    "Spotify":      {"url":  "https://open.spotify.com/user/{}",
                     "ok":   "\"type\":\"user\"",
                     "reliable": True},
    # ── Dev / Tech ───────────────────────────────────────────────────────────
    "GitHub":       {"url":  "https://github.com/{}",
                     "api":  "https://api.github.com/users/{}",
                     "ok":   "\"login\":",
                     "reliable": True},
    "GitLab":       {"url":  "https://gitlab.com/{}",
                     "api":  "https://gitlab.com/api/v4/users?username={}",
                     "ok":   "\"username\":",
                     "reliable": True},
    "Patreon":      {"url":  "https://www.patreon.com/{}",
                     "code": 404,
                     "reliable": False},
    "Replit":       {"url":  "https://replit.com/@{}",
                     "code": 404,
                     "reliable": False},
    "HackerNews":   {"url":  "https://news.ycombinator.com/user?id={}",
                     "err":  "No such user",
                     "reliable": True},
    "Steam":        {"url":  "https://steamcommunity.com/id/{}",
                     "err":  "The specified profile could not be found",
                     "reliable": True},
    # ── CIS / DACH / International ───────────────────────────────────────────
    "VK":           {"url":  "https://vk.com/{}",
                     "err":  "This page no longer exists",
                     "reliable": True},
    "OK.ru":        {"url":  "https://ok.ru/{}",
                     "code": 404,
                     "reliable": False},
    "XING":         {"url":  "https://www.xing.com/profile/{}",
                     "code": 404,
                     "reliable": False},
    # ── Foren / Nischen ──────────────────────────────────────────────────────
    "Medium":       {"url":  "https://medium.com/@{}",
                     "code": 404,
                     "reliable": False},
    "Substack":     {"url":  "https://{}.substack.com/",
                     "code": 404,
                     "reliable": False},
    "Quora":        {"url":  "https://www.quora.com/profile/{}",
                     "code": 404,
                     "reliable": False},
    "Wikipedia":    {"url":  "https://en.wikipedia.org/wiki/User:{}",
                     "err":  "does not exist",
                     "reliable": True},
    "About.me":     {"url":  "https://about.me/{}",
                     "code": 404,
                     "reliable": False},
    "Linktree":     {"url":  "https://linktr.ee/{}",
                     "api":  "https://linktr.ee/api/v1/profiles/{}",
                     "ok":   "\"username\":",
                     "reliable": True},
    "Behance":      {"url":  "https://www.behance.net/{}",
                     "code": 404,
                     "reliable": False},
    "DeviantArt":   {"url":  "https://www.deviantart.com/{}",
                     "code": 404,
                     "reliable": False},
    "500px":        {"url":  "https://500px.com/p/{}",
                     "code": 404,
                     "reliable": False},
    "Vimeo":        {"url":  "https://vimeo.com/{}",
                     "code": 404,
                     "reliable": False},
    "Dailymotion":  {"url":  "https://www.dailymotion.com/{}",
                     "err":  "This channel does not exist",
                     "reliable": True},
    "Kick.com":     {"url":  "https://kick.com/{}",
                     "api":  "https://kick.com/api/v1/channels/{}",
                     "ok":   "\"slug\":",
                     "reliable": True},
    "Rumble":       {"url":  "https://rumble.com/c/{}",
                     "code": 404,
                     "reliable": False},
    "Odysee":       {"url":  "https://odysee.com/@{}",
                     "err":  "Page Not Found",
                     "reliable": True},
    "Mastodon":     {"url":  "https://mastodon.social/@{}",
                     "api":  "https://mastodon.social/api/v1/accounts/lookup?acct={}",
                     "ok":   "\"username\":",
                     "reliable": True},
    "Bluesky":      {"url":  "https://bsky.app/profile/{}",
                     "api":  "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={}.bsky.social",
                     "ok":   "did",
                     "reliable": True},
    "Threads":      {"url":  "https://www.threads.net/@{}",
                     "err":  "Sorry, this page",
                     "reliable": True},
    "OnlyFans":     {"url":  "https://onlyfans.com/{}",
                     "code": 404,
                     "reliable": False},
    "Fansly":       {"url":  "https://fansly.com/{}",
                     "code": 404,
                     "reliable": False},
    "Vsco":         {"url":  "https://vsco.co/{}",
                     "err":  "page not found",
                     "reliable": True},
    "Poshmark":     {"url":  "https://poshmark.com/closet/{}",
                     "err":  "page not found",
                     "reliable": True},
    "Etsy":         {"url":  "https://www.etsy.com/people/{}",
                     "code": 404,
                     "reliable": False},
    "Cashapp":      {"url":  "https://cash.app/${}",
                     "err":  "$cashtag not found",
                     "reliable": True},
    "Venmo":        {"url":  "https://venmo.com/{}",
                     "code": 404,
                     "reliable": False},
    "Chess.com":    {"url":  "https://www.chess.com/member/{}",
                     "code": 404,
                     "reliable": False},
    # ── Neu hinzugefügt ──────────────────────────────────────────────────────
    "Twitch (clips)": {"url": "https://clips.twitch.tv/{}",
                       "code": 404,
                       "reliable": False},
    "Telegram":     {"url":  "https://t.me/{}",
                     "err":  "If you have Telegram",
                     "reliable": True},
    "Discord":      {"url":  "https://discord.com/invite/{}",
                     "err":  "Invite Invalid",
                     "reliable": True},
    "WhatsApp":     {"url":  "https://wa.me/{}",
                     "code": 404,
                     "reliable": False},
    "Ask.fm":       {"url":  "https://ask.fm/{}",
                     "code": 404,
                     "reliable": False},
    "Clubhouse":    {"url":  "https://www.joinclubhouse.com/@{}",
                     "code": 404,
                     "reliable": False},
    "Letterboxd":   {"url":  "https://letterboxd.com/{}",
                     "err":  "Sorry, we can",
                     "reliable": True},
    "Last.fm":      {"url":  "https://www.last.fm/user/{}",
                     "code": 404,
                     "reliable": False},
    "Goodreads":    {"url":  "https://www.goodreads.com/{}",
                     "code": 404,
                     "reliable": False},
    "Duolingo":     {"url":  "https://www.duolingo.com/profile/{}",
                     "api":  "https://www.duolingo.com/2017-06-30/users?username={}",
                     "ok":   "\"username\":",
                     "reliable": True},
    "Strava":       {"url":  "https://www.strava.com/athletes/{}",
                     "code": 404,
                     "reliable": False},
    "Mix":          {"url":  "https://mix.com/{}",
                     "code": 404,
                     "reliable": False},
    "Fiverr":       {"url":  "https://www.fiverr.com/{}",
                     "code": 404,
                     "reliable": False},
    "Freelancer":   {"url":  "https://www.freelancer.com/u/{}",
                     "code": 404,
                     "reliable": False},
    "Upwork":       {"url":  "https://www.upwork.com/freelancers/~{}",
                     "code": 404,
                     "reliable": False},
    "Gumroad":      {"url":  "https://gumroad.com/{}",
                     "code": 404,
                     "reliable": False},
    "Ko-fi":        {"url":  "https://ko-fi.com/{}",
                     "code": 404,
                     "reliable": False},
    "BuyMeACoffee": {"url":  "https://buymeacoffee.com/{}",
                     "api":  "https://backend.buymeacoffee.com/api/v1/page/{}",
                     "ok":   "\"vanity\":",
                     "reliable": True},
    "Triller":      {"url":  "https://triller.co/@{}",
                     "code": 404,
                     "reliable": False},
    "Likee":        {"url":  "https://likee.video/@{}",
                     "code": 404,
                     "reliable": False},
    "Kwai":         {"url":  "https://www.kwai.com/@{}",
                     "code": 404,
                     "reliable": False},
}

_CHECK_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/122.0.0.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
}
_print_lock = threading.Lock()

# ─── Konstanten ───────────────────────────────────────────────────────────────
SUPPORTED_EXTS  = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif"}
SIMILARITY_HIGH = 0.60   # >60% = sehr wahrscheinlich dieselbe Person
SIMILARITY_MED  = 0.45   # >45% = möglicherweise dieselbe Person
OUTPUT_DIR      = Path("osint_output")
BANNER = """
╔══════════════════════════════════════════════════════╗
║          OSINT Face Finder  //  KI-Gesichtssuche     ║
╚══════════════════════════════════════════════════════╝"""

# ─── Hilfs-Farben für Terminal-Output ─────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):   print(f"{C.GREEN}[+]{C.RESET} {msg}")
def info(msg): print(f"{C.CYAN}[*]{C.RESET} {msg}")
def warn(msg): print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}[-]{C.RESET} {msg}")
def bold(msg): print(f"{C.BOLD}{msg}{C.RESET}")

# ─── KI-Modell laden ──────────────────────────────────────────────────────────
def load_model(gpu: bool = True) -> FaceAnalysis:
    """
    Lädt buffalo_l – das genaueste öffentliche InsightFace-Modell.
    Erkennt Gesicht, Alter, Geschlecht + 512-dim Embeddings (ArcFace).
    """
    providers = (
        ["CUDAExecutionProvider", "CPUExecutionProvider"]
        if gpu else
        ["CPUExecutionProvider"]
    )
    info("Lade KI-Modell (buffalo_l – ArcFace 512d) …")
    model = FaceAnalysis(name="buffalo_l", providers=providers)
    # det_size=640 = maximale Genauigkeit, findet auch kleine/seitliche Gesichter
    model.prepare(ctx_id=0 if gpu else -1, det_size=(640, 640))
    ok("Modell geladen.")
    return model

# ─── Gesichter aus Bild extrahieren ───────────────────────────────────────────
def get_faces(model: FaceAnalysis, image_path: str):
    """
    Liest ein Bild, gibt (img, faces) zurück.
    face-Objekte haben: .bbox .embedding .age .gender .det_score .kps
    """
    img = cv2.imread(str(image_path))
    if img is None:
        try:
            from PIL import Image
            pil = Image.open(str(image_path)).convert("RGB")
            img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
        except Exception:
            err(f"Bild konnte nicht gelesen werden: {image_path}")
            return None, None
    faces = model.get(img)
    return img, faces

# ─── Ausgerichtetes Gesicht (112×112, ideal für ArcFace) ─────────────────────
def get_aligned_crop(img, face, size=112) -> np.ndarray:
    return face_align.norm_crop(img, landmark=face.kps, image_size=size)

# ─── Kosinus-Ähnlichkeit ──────────────────────────────────────────────────────
def cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    a = a / (np.linalg.norm(a) + 1e-9)
    b = b / (np.linalg.norm(b) + 1e-9)
    return float(np.dot(a, b))

# ─── Qualitäts-Score ──────────────────────────────────────────────────────────
def face_quality(face) -> str:
    s = face.det_score
    if s >= 0.85: return f"{C.GREEN}★★★ Top{C.RESET} ({s:.2f})"
    if s >= 0.65: return f"{C.YELLOW}★★☆ Gut{C.RESET} ({s:.2f})"
    return f"{C.RED}★☆☆ Niedrig{C.RESET} ({s:.2f})"

# ─── Bild mit Annotierungen speichern ─────────────────────────────────────────
def save_annotated(img, faces, out_path: Path, matches=None):
    vis = img.copy()
    for i, face in enumerate(faces):
        x1, y1, x2, y2 = face.bbox.astype(int)
        gender = "M" if face.gender == 1 else "F"
        label  = f"P{i+1} {gender} ~{int(face.age)}J"
        color  = (0, 200, 0)
        if matches is not None and i < len(matches):
            sim = matches[i]
            if   sim >= SIMILARITY_HIGH: color = (0, 255, 100); label += f" ✓{sim:.0%}"
            elif sim >= SIMILARITY_MED:  color = (0, 200, 255); label += f" ?{sim:.0%}"
            else:                        color = (60, 60, 200);  label += f" ✗{sim:.0%}"
        cv2.rectangle(vis, (x1, y1), (x2, y2), color, 2)
        cv2.putText(vis, label, (x1, max(y1 - 8, 0)),
                    cv2.FONT_HERSHEY_DUPLEX, 0.55, color, 1, cv2.LINE_AA)
    cv2.imwrite(str(out_path), vis)
    ok(f"Annotiertes Bild → {out_path}")

# ─── MODUS 1: Bild analysieren ────────────────────────────────────────────────
def cmd_analyze(model, image_path: str):
    bold(f"\n── Analyse: {image_path} ──")
    img, faces = get_faces(model, image_path)
    if img is None: return
    if not faces:
        warn("Keine Gesichter gefunden. Tipp: Bild schärfer / frontaler.")
        return

    ok(f"{len(faces)} Person(en) erkannt.\n")
    OUTPUT_DIR.mkdir(exist_ok=True)
    results = []

    for i, face in enumerate(faces):
        gender   = "Mann" if face.gender == 1 else "Frau"
        bbox     = face.bbox.astype(int)
        pad      = 20
        h, w     = img.shape[:2]
        crop     = img[max(0, bbox[1]-pad):min(h, bbox[3]+pad),
                       max(0, bbox[0]-pad):min(w, bbox[2]+pad)]
        crop_f   = OUTPUT_DIR / f"face_{i+1}.jpg"
        ali_f    = OUTPUT_DIR / f"face_{i+1}_aligned.jpg"
        cv2.imwrite(str(crop_f), crop)
        cv2.imwrite(str(ali_f), get_aligned_crop(img, face))

        bold(f"  ─── Person {i+1} ───────────────────────────")
        info(f"  Geschlecht : {gender}")
        info(f"  Alter      : ~{int(face.age)} Jahre")
        info(f"  Qualität   : {face_quality(face)}")
        info(f"  Position   : {bbox.tolist()}")
        ok  (f"  Crop       : {crop_f}")
        ok  (f"  Aligned    : {ali_f}  ← Diese Datei für Reverse-Search verwenden!")

        print(f"\n  {C.BOLD}Reverse-Image-Search (manueller Upload):{C.RESET}")
        links = {
            "Google Lens":         "https://lens.google.com/",
            "Yandex Bilder":       "https://yandex.com/images/",
            "Bing Visual Search":  "https://www.bing.com/visualsearch",
            "PimEyes (Face only)": "https://pimeyes.com/",
            "FaceCheck.ID":        "https://facecheck.id/",
            "Social Catfish":      "https://socialcatfish.com/",
        }
        for name, url in links.items():
            print(f"    {C.BLUE}{name:<25}{C.RESET}  {url}")
        print()

        results.append({
            "person": i + 1,
            "gender": gender,
            "age_estimate": int(face.age),
            "det_score": round(float(face.det_score), 4),
            "bbox": bbox.tolist(),
            "crop": str(crop_f),
            "aligned": str(ali_f),
        })

    ann_path = OUTPUT_DIR / f"annotated_{Path(image_path).name}"
    save_annotated(img, faces, ann_path)

    # Embeddings für spätere Vergleiche sichern
    emb_file = OUTPUT_DIR / "embeddings.npz"
    np.savez(str(emb_file), **{f"face_{i+1}": faces[i].embedding for i in range(len(faces))})
    ok(f"Embeddings gespeichert → {emb_file}")

    rpt_path = OUTPUT_DIR / "report.json"
    rpt_path.write_text(
        json.dumps({"timestamp": datetime.now().isoformat(),
                    "source_image": str(image_path),
                    "faces_found": len(faces),
                    "persons": results}, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    ok(f"Report     → {rpt_path}")

# ─── MODUS 2: Ordner nach Ziel-Person durchsuchen ────────────────────────────
def cmd_scan(model, target_path: str, scan_dir: str, threshold: float):
    bold(f"\n── Ziel-Person : {target_path}")
    bold(f"── Scanne      : {scan_dir}  (Schwelle: {threshold:.0%})\n")

    t_img, t_faces = get_faces(model, target_path)
    if t_img is None or not t_faces:
        err("Kein Gesicht im Ziel-Bild!"); return
    if len(t_faces) > 1:
        warn("Mehrere Gesichter im Ziel → nehme das mit der höchsten Qualität.")

    target_face = max(t_faces, key=lambda f: f.det_score)
    t_emb       = target_face.embedding / (np.linalg.norm(target_face.embedding) + 1e-9)
    ok(f"Ziel-Embedding geladen (Qualität: {face_quality(target_face)})\n")

    files = [f for f in Path(scan_dir).rglob("*") if f.suffix.lower() in SUPPORTED_EXTS]
    if not files:
        err(f"Keine Bilder in '{scan_dir}' gefunden."); return

    info(f"{len(files)} Bild(er) werden gescannt …\n")
    OUTPUT_DIR.mkdir(exist_ok=True)
    hits = []

    for idx, fpath in enumerate(files, 1):
        sys.stdout.write(f"\r{C.CYAN}[{idx}/{len(files)}]{C.RESET} {str(fpath.name)[:55]:<55}")
        sys.stdout.flush()
        img, faces = get_faces(model, str(fpath))
        if img is None or not faces: continue

        for face in faces:
            emb = face.embedding / (np.linalg.norm(face.embedding) + 1e-9)
            sim = float(np.dot(t_emb, emb))
            if sim >= threshold:
                hits.append({
                    "file": str(fpath),
                    "similarity": round(sim, 4),
                    "gender": "Mann" if face.gender == 1 else "Frau",
                    "age": int(face.age),
                    "det_score": round(float(face.det_score), 4),
                    "bbox": face.bbox.astype(int).tolist(),
                })

    print()
    bold(f"\n── Ergebnisse ──────────────────────────────────────")

    if not hits:
        warn("Niemanden gefunden.")
        warn(f"Tipp: --threshold auf {max(0.25, threshold - 0.10):.2f} senken und erneut versuchen.")
    else:
        hits.sort(key=lambda h: h["similarity"], reverse=True)
        ok(f"{len(hits)} Treffer!\n")
        for h in hits:
            sim  = h["similarity"]
            bar  = "█" * int(sim * 25) + "░" * (25 - int(sim * 25))
            tag  = (f"{C.GREEN}✔ SEHR WAHRSCHEINLICH{C.RESET}" if sim >= SIMILARITY_HIGH
                    else f"{C.YELLOW}? MÖGLICH{C.RESET}")
            print(f"  {tag}")
            print(f"  [{bar}] {sim:.1%}  |  {h['gender']}, ~{h['age']} J.")
            print(f"  Datei: {h['file']}\n")
        _save_hits_collage(hits, OUTPUT_DIR / "treffer_collage.jpg")

    rpt = {"timestamp": datetime.now().isoformat(), "target": target_path,
           "scanned": len(files), "threshold": threshold, "hits": hits}
    rpt_path = OUTPUT_DIR / "scan_report.json"
    rpt_path.write_text(json.dumps(rpt, indent=2, ensure_ascii=False), encoding="utf-8")
    ok(f"Report → {rpt_path}")

def _save_hits_collage(hits: list, out_path: Path, max_n: int = 16):
    tiles = []
    for h in hits[:max_n]:
        img = cv2.imread(h["file"])
        if img is None: continue
        b = h["bbox"]
        crop = img[max(0, b[1]):b[3], max(0, b[0]):b[2]]
        if crop.size == 0: continue
        crop  = cv2.resize(crop, (150, 150))
        sim   = h["similarity"]
        color = (0, 220, 80) if sim >= SIMILARITY_HIGH else (0, 200, 255)
        cv2.rectangle(crop, (0, 0), (149, 149), color, 3)
        cv2.putText(crop, f"{sim:.0%}", (4, 20),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.65, color, 2)
        tiles.append(crop)
    if not tiles: return
    cols   = min(4, len(tiles))
    rows   = (len(tiles) + cols - 1) // cols
    canvas = np.zeros((rows * 150, cols * 150, 3), dtype=np.uint8)
    for i, t in enumerate(tiles):
        r, c = divmod(i, cols)
        canvas[r*150:(r+1)*150, c*150:(c+1)*150] = t
    cv2.imwrite(str(out_path), canvas)
    ok(f"Treffer-Collage → {out_path}")

# ─── MODUS 4: Username auf Social Media suchen ──────────────────────────────
def _check_platform(name: str, cfg: dict, username: str) -> tuple:
    """
    Prüft ob 'username' auf einer Plattform existiert.
    Gibt (name, profile_url, found: bool, note: str, reliable: bool) zurück.
    """
    profile_url = cfg["url"].format(username)
    check_url   = cfg["api"].format(username) if "api" in cfg else profile_url
    err_str     = cfg.get("err", None)
    ok_str      = cfg.get("ok", None)
    exp_code    = cfg.get("code", 404)
    reliable    = cfg.get("reliable", False)

    try:
        if _REQUESTS_OK:
            r    = _req.get(check_url, headers=_CHECK_HEADERS,
                            timeout=12, allow_redirects=True)
            code = r.status_code
            body = r.text
        else:
            req  = urllib.request.Request(check_url, headers=_CHECK_HEADERS)
            with urllib.request.urlopen(req, timeout=12) as resp:
                code = resp.status
                body = resp.read(500).decode("utf-8", errors="ignore")

        if code == 200:
            if ok_str:
                # Must contain ok_str to be confirmed
                found = ok_str.lower() in body.lower()
                return name, profile_url, found, f"API {code}" if found else "API-Check negativ", reliable
            if err_str and err_str.lower() in body.lower():
                return name, profile_url, False, "User-Fehlerseite erkannt", reliable
            return name, profile_url, True, f"HTTP {code}", reliable
        elif code in (301, 302, 308):
            return name, profile_url, False, f"Redirect ({code})", reliable
        else:
            return name, profile_url, False, f"HTTP {code}", reliable
    except Exception as e:
        short = str(e)[:60]
        return name, profile_url, None, f"Fehler: {short}", reliable


def cmd_username(username: str, workers: int = 20):
    bold(f"\n── Username-Suche: '{username}' auf {len(PLATFORMS)} Plattformen ──\n")
    results  = {"found": [], "not_found": [], "error": []}
    total    = len(PLATFORMS)
    done     = {"n": 0}
    found_n  = {"n": 0}

    def _cb(future):
        name, url, found, note = future.result()
        done["n"] += 1
        pct = done["n"] / total * 100
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        with _print_lock:
            sys.stdout.write(
                f"\r{C.CYAN}[{done['n']:>2}/{total}]{C.RESET} "
                f"[{bar}] {pct:5.1f}%  Gefunden: {C.GREEN}{found_n['n']}{C.RESET}  "
                f"Prüfe: {name:<20}"
            )
            sys.stdout.flush()
        if found is True:
            found_n["n"] += 1
            results["found"].append({"platform": name, "url": url, "note": note})
        elif found is False:
            results["not_found"].append({"platform": name, "url": url})
        else:
            results["error"].append({"platform": name, "note": note})

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(_check_platform, name, cfg, username)
            for name, cfg in PLATFORMS.items()
        ]
        for f in futures:
            f.add_done_callback(_cb)
        concurrent.futures.wait(futures)

    print()  # Zeilenumbruch
    bold(f"\n── Ergebnisse für '@{username}' ─────────────────────────────────")

    if not results["found"]:
        warn("Kein Account auf den geprüften Plattformen gefunden.")
        warn("Tipp: Versuche Spitznamen, Geburtsjahrgang, Länderkürzel usw.")
    else:
        ok(f"{len(results['found'])} Account(s) gefunden:\n")
        for r in results["found"]:
            tag = f"{C.GREEN}✔  GEFUNDEN{C.RESET}"
            print(f"  {tag}  {C.BOLD}{r['platform']:<20}{C.RESET}  {r['url']}")

    if results["not_found"]:
        print(f"\n  {C.YELLOW}Nicht gefunden ({len(results['not_found'])}):{C.RESET} "
              + ", ".join(r["platform"] for r in results["not_found"]))

    # JSON-Report
    OUTPUT_DIR.mkdir(exist_ok=True)
    rpt = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "platforms_checked": total,
        "found": results["found"],
        "not_found": [r["platform"] for r in results["not_found"]],
        "errors": results["error"],
    }
    rpt_path = OUTPUT_DIR / f"username_{username}.json"
    rpt_path.write_text(json.dumps(rpt, indent=2, ensure_ascii=False), encoding="utf-8")
    ok(f"\nReport → {rpt_path}")


# ─── MODUS 5: Gesicht → Social Media Links ───────────────────────────────────
def cmd_social(model, image_path: str, open_browser: bool = False):
    """
    Extrahiert das Gesicht aus einem Foto und
    - zeigt alle relevanten Face-Search-Engines mit Anleitung
    - öffnet optional die wichtigsten direkt im Browser
    """
    bold(f"\n── Social-Media-Suche via Gesichtsbild: {image_path} ──\n")
    img, faces = get_faces(model, image_path)
    if img is None: return
    if not faces:
        warn("Kein Gesicht gefunden. Tipp: Klareres, frontaleres Bild nutzen.")
        return

    best   = max(faces, key=lambda f: f.det_score)
    OUTPUT_DIR.mkdir(exist_ok=True)
    ali_f  = OUTPUT_DIR / "social_search_face.jpg"
    cv2.imwrite(str(ali_f), get_aligned_crop(img, best, size=300))
    ok(f"Gesicht extrahiert → {ali_f}")
    ok(f"Qualität: {face_quality(best)}")

    ABS_PATH = str(ali_f.resolve())

    print(f"""
  {C.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
  {C.YELLOW}SCHRITT 1{C.RESET}  Gesicht-Datei liegt hier:
             {C.CYAN}{ABS_PATH}{C.RESET}

  {C.YELLOW}SCHRITT 2{C.RESET}  Öffne eine der Seiten unten und lade die Datei hoch:
  {C.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}""")

    SOCIAL_SITES = [
        ("★★★", "PimEyes",
         "https://pimeyes.com/",
         "Beste Gesichts-Suchmaschine – findet Social-Media, Nachrichtenartikel, Blogs"),
        ("★★★", "FaceCheck.ID",
         "https://facecheck.id/",
         "Direkte Social-Media Profilsuche (Instagram, TikTok, Twitter, Facebook)"),
        ("★★★", "Yandex Bilder",
         "https://yandex.com/images/",
         "Yandex findet oft Profile die Google nicht findet – sehr gut für CIS-Raum"),
        ("★★☆", "Google Lens",
         "https://lens.google.com/",
         "Findet ähnliche Bilder und verlinkte Webseiten"),
        ("★★☆", "Bing Visual Search",
         "https://www.bing.com/visualsearch",
         "Microsofts Reverse-Search – gut für lateinamerikanische / asiatische Profile"),
        ("★★☆", "Social Catfish",
         "https://socialcatfish.com/",
         "Spezialisiert auf Personen-Suche, Fake-Profil-Erkennung"),
        ("★★☆", "TinEye",
         "https://tineye.com/",
         "Findet exakt gleiche Bild-Uploads auf anderen Webseiten"),
        ("★☆☆", "Lenso.ai",
         "https://lenso.ai/",
         "KI-gestützt, findet Duplikate und ähnliche Personen-Fotos"),
        ("★☆☆", "Search4Faces",
         "https://search4faces.com/",
         "Fokus auf russische/ukrainische Social Media (VK, OK.ru)"),
    ]

    for stars, name, url, desc in SOCIAL_SITES:
        print(f"  {C.CYAN}{stars}{C.RESET}  {C.BOLD}{name:<20}{C.RESET}  {url}")
        print(f"             {C.YELLOW}{desc}{C.RESET}\n")

    print(f"  {C.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"  {C.YELLOW}SCHRITT 3{C.RESET}  Wenn du einen Benutzernamen findest, nutze:")
    print(f"             {C.CYAN}python app.py --username <gefundener_name>{C.RESET}")
    print(f"             → prüft 50+ Plattformen auf diesen Username\n")

    if open_browser:
        info("Öffne PimEyes und FaceCheck.ID im Browser …")
        webbrowser.open("https://pimeyes.com/")
        time.sleep(0.5)
        webbrowser.open("https://facecheck.id/")
        time.sleep(0.5)
        webbrowser.open("https://yandex.com/images/")

    # Report
    rpt = {
        "timestamp": datetime.now().isoformat(),
        "source_image": str(image_path),
        "aligned_face": str(ali_f),
        "face_quality": round(float(best.det_score), 4),
        "gender_estimate": "Mann" if best.gender == 1 else "Frau",
        "age_estimate": int(best.age),
        "search_sites": [{"name": n, "url": u} for _, n, u, _ in SOCIAL_SITES],
    }
    rpt_path = OUTPUT_DIR / "social_report.json"
    rpt_path.write_text(json.dumps(rpt, indent=2, ensure_ascii=False), encoding="utf-8")
    ok(f"Report → {rpt_path}")


# ─── MODUS 3: Zwei Bilder direkt vergleichen ─────────────────────────────────
def cmd_compare(model, target_path: str, compare_path: str):
    bold(f"\n── Vergleich ──────────────────────────────")
    bold(f"  Bild A (Ziel)    : {target_path}")
    bold(f"  Bild B (Vergleich): {compare_path}\n")

    a_img, a_faces = get_faces(model, target_path)
    b_img, b_faces = get_faces(model, compare_path)
    if a_img is None or not a_faces: err("Kein Gesicht in Bild A."); return
    if b_img is None or not b_faces: err("Kein Gesicht in Bild B."); return

    a_face  = max(a_faces, key=lambda f: f.det_score)
    a_emb   = a_face.embedding / (np.linalg.norm(a_face.embedding) + 1e-9)
    bold(f"  Bild A: {len(a_faces)} Gesicht(er)  │  Bild B: {len(b_faces)} Gesicht(er)\n")

    OUTPUT_DIR.mkdir(exist_ok=True)
    sims = []
    for i, face in enumerate(b_faces):
        emb = face.embedding / (np.linalg.norm(face.embedding) + 1e-9)
        sim = float(np.dot(a_emb, emb))
        sims.append(sim)
        bar = "█" * int(sim * 30) + "░" * (30 - int(sim * 30))
        if   sim >= SIMILARITY_HIGH: verdict = f"{C.GREEN}✔  MATCH – sehr wahrscheinlich dieselbe Person!{C.RESET}"
        elif sim >= SIMILARITY_MED:  verdict = f"{C.YELLOW}?  MÖGLICH – könnte dieselbe Person sein{C.RESET}"
        else:                        verdict = f"{C.RED}✘  KEIN MATCH{C.RESET}"
        print(f"  Person B-{i+1}: [{bar}] {sim:.1%}")
        print(f"             {verdict}")
        print(f"             Alter: ~{int(face.age)} J.  |  det_score: {face.det_score:.2f}\n")

    save_annotated(b_img, b_faces,
                   OUTPUT_DIR / f"compare_{Path(compare_path).name}", matches=sims)

    # Side-by-Side speichern
    a_crop  = get_aligned_crop(a_img, a_face, size=200)
    b_crop  = get_aligned_crop(b_img, b_faces[int(np.argmax(sims))], size=200)
    divider = np.full((200, 10, 3), 255, dtype=np.uint8)
    cv2.imwrite(str(OUTPUT_DIR / "side_by_side.jpg"), np.hstack([a_crop, divider, b_crop]))
    ok(f"Side-by-Side → {OUTPUT_DIR / 'side_by_side.jpg'}")

# ─── CLI ─────────────────────────────────────────────────────────────────────
# ─── MODUS 6: Klarnamen-Suche (Google Dorks) ────────────────────────────────
def cmd_name(name: str, extra: str = ""):
    """Generiert Google/Yandex/Bing Dork-Links für einen Klarnamen."""
    q      = urllib.parse.quote_plus(f'"{name}"')
    qe     = urllib.parse.quote_plus(f'"{name}" {extra}') if extra else q
    bold(f"\n{'─'*60}")
    bold(f"  NAMENS-SUCHE: {name}")
    bold(f"{'─'*60}\n")

    dorks = [
        ("Google  – Alle Ergebnisse",
         f"https://www.google.com/search?q={qe}"),
        ("Google  – Nur Instagram",
         f"https://www.google.com/search?q={q}+site:instagram.com"),
        ("Google  – Nur TikTok",
         f"https://www.google.com/search?q={q}+site:tiktok.com"),
        ("Google  – Nur Facebook",
         f"https://www.google.com/search?q={q}+site:facebook.com"),
        ("Google  – Nur LinkedIn",
         f"https://www.google.com/search?q={q}+site:linkedin.com"),
        ("Google  – Nur Twitter/X",
         f"https://www.google.com/search?q={q}+site:x.com"),
        ("Google  – Nur YouTube",
         f"https://www.google.com/search?q={q}+site:youtube.com"),
        ("Google  – Nur Reddit",
         f"https://www.google.com/search?q={q}+site:reddit.com"),
        ("Google  – Nur VK",
         f"https://www.google.com/search?q={q}+site:vk.com"),
        ("Yandex  – Alle",
         f"https://yandex.com/search/?text={qe}"),
        ("Bing    – Alle",
         f"https://www.bing.com/search?q={qe}"),
        ("DuckDuckGo – Alle",
         f"https://duckduckgo.com/?q={qe}"),
        ("True People Search",
         f"https://www.truepeoplesearch.com/results?name={urllib.parse.quote_plus(name)}"),
        ("Spokeo (USA)",
         f"https://www.spokeo.com/{urllib.parse.quote_plus(name)}"),
    ]

    for label, url in dorks:
        print(f"  {C.BLUE}{label:<30}{C.RESET}  {url}")

    print(f"\n  {C.YELLOW}[!]{C.RESET} Tipp: Kopiere die Links in deinen Browser.")
    print(f"       Mit --open-browser öffnet das Script sie automatisch.\n")

    OUTPUT_DIR.mkdir(exist_ok=True)
    rpt = {"timestamp": datetime.now().isoformat(), "name": name,
            "extra": extra, "dorks": [{"label": l, "url": u} for l, u in dorks]}
    rpt_path = OUTPUT_DIR / f"name_{name.replace(' ', '_')}.json"
    rpt_path.write_text(json.dumps(rpt, indent=2, ensure_ascii=False), encoding="utf-8")
    ok(f"Report → {rpt_path}")


def build_parser():
    p = argparse.ArgumentParser(
        description="OSINT Face Finder – KI-gestützte Gesichtssuche",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Beispiele:
  python app.py                                   # interaktives Menue
  python app.py --username max_mustermann
  python app.py --username max.mueller --reliable
  python app.py --name "Anna Mueller" --extra Deutschland
  python app.py --social schwester.jpg --open-browser
  python app.py --analyze test.jpg
  python app.py --target oma.jpg --scan C:\\Fotos
  python app.py --target oma.jpg --compare bild2.jpg
"""
    )
    p.add_argument("--analyze",      metavar="BILD",     help="Alle Gesichter in einem Bild analysieren")
    p.add_argument("--target",       metavar="BILD",     help="Referenz-Foto der gesuchten Person")
    p.add_argument("--scan",         metavar="ORDNER",   help="Ordner rekursiv nach Ziel-Person durchsuchen")
    p.add_argument("--compare",      metavar="BILD",     help="Einzelnes Bild mit Ziel-Person vergleichen")
    p.add_argument("--threshold",    metavar="0.0-1.0",  type=float, default=0.45,
                   help="Ähnlichkeits-Schwelle für --scan (Standard: 0.45)")
    p.add_argument("--username",     metavar="NAME",
                   help="Username auf 60+ Plattformen suchen")
    p.add_argument("--reliable",     action="store_true",
                   help="Bei --username: nur zuverlässige Checks")
    p.add_argument("--name",         metavar="KLARNAME",
                   help="Klarnamen-Suche mit Google/Yandex Dorks (z.B. \"Anna Mueller\")")
    p.add_argument("--extra",        metavar="SUCHBEGRIFF", default="",
                   help="Zusatz für --name Suche (z.B. Stadt, Land, Schule)")
    p.add_argument("--social",       metavar="BILD",
                   help="Gesicht extrahieren + alle Social-Search-Links")
    p.add_argument("--open-browser", action="store_true",
                   help="Bei --social/--name: öffnet Seiten direkt im Browser")
    p.add_argument("--cpu",          action="store_true", help="Nur CPU (kein CUDA/GPU)")
    return p

def main():
    # Windows: UTF-8 Ausgabe erzwingen + ANSI-Farben aktivieren
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.system("")  # Windows ANSI aktivieren
    print(C.CYAN + BANNER + C.RESET)

    parser = build_parser()
    if len(sys.argv) == 1:
        _interactive_menu()
        return

    args = parser.parse_args()
    t0   = time.time()

    # ── Direkte Modi ohne KI-Modell ──────────────────────────────────────────
    if args.username:
        cmd_username(args.username, only_reliable=args.reliable)
        info(f"Fertig in {time.time() - t0:.1f}s  |  Ergebnisse: {OUTPUT_DIR.resolve()}")
        return

    if args.name:
        cmd_name(args.name, extra=args.extra)
        if args.open_browser:
            q = urllib.parse.quote_plus(f'"{args.name}" {args.extra}'.strip())
            webbrowser.open(f"https://www.google.com/search?q={q}")
        info(f"Fertig in {time.time() - t0:.1f}s")
        return

    # ── KI-Modell laden ──────────────────────────────────────────────────────
    model = load_model(gpu=not args.cpu)

    if args.analyze:
        if not Path(args.analyze).exists(): err(f"Nicht gefunden: {args.analyze}"); sys.exit(1)
        cmd_analyze(model, args.analyze)

    elif args.social:
        if not Path(args.social).exists(): err(f"Nicht gefunden: {args.social}"); sys.exit(1)
        cmd_social(model, args.social, open_browser=args.open_browser)

    elif args.target and args.scan:
        for p in (args.target, args.scan):
            if not Path(p).exists(): err(f"Nicht gefunden: {p}"); sys.exit(1)
        cmd_scan(model, args.target, args.scan, args.threshold)

    elif args.target and args.compare:
        for p in (args.target, args.compare):
            if not Path(p).exists(): err(f"Nicht gefunden: {p}"); sys.exit(1)
        cmd_compare(model, args.target, args.compare)

    else:
        err("Ungültige Kombination. --help für Hilfe.")
        sys.exit(1)

    info(f"Fertig in {time.time() - t0:.1f}s  │  Ergebnisse in: {OUTPUT_DIR.resolve()}")

# ─── Interaktives Menü ───────────────────────────────────────────────────────
def _interactive_menu():
    """Wird gestartet wenn python app.py ohne Argumente aufgerufen wird."""
    t0 = time.time()
    while True:
        print(f"""
  {C.BOLD}{'─'*54}{C.RESET}
  {C.CYAN}[1]{C.RESET}  Username suchen        (60+ Plattformen)
  {C.CYAN}[2]{C.RESET}  Klarname / Google Dorks suchen
  {C.CYAN}[3]{C.RESET}  Gesicht analysieren    (Foto hochladen)
  {C.CYAN}[4]{C.RESET}  Social-Media von Foto  (Face → Links)
  {C.CYAN}[5]{C.RESET}  Zwei Fotos vergleichen (Selbe Person?)
  {C.CYAN}[6]{C.RESET}  Ordner durchsuchen     (Face-Scan)
  {C.RED}[Q]{C.RESET}  Beenden
  {C.BOLD}{'─'*54}{C.RESET}""")
        choice = input(f"  {C.BOLD}Waehle [1-6 / Q]: {C.RESET}").strip().lower()

        if choice == "q":
            print(f"  {C.YELLOW}Beendet.{C.RESET}\n")
            break

        elif choice == "1":
            u = input(f"  {C.CYAN}Username eingeben: {C.RESET}").strip()
            if not u: warn("Kein Username eingegeben."); continue
            r = input(f"  Nur zuverlaessige Checks? [j/N]: ").strip().lower()
            cmd_username(u, only_reliable=(r == "j"))

        elif choice == "2":
            n = input(f"  {C.CYAN}Klarname (z.B. Anna Mueller): {C.RESET}").strip()
            if not n: warn("Kein Name eingegeben."); continue
            e = input(f"  Zusatz (Stadt/Land/leer lassen): {C.RESET}").strip()
            cmd_name(n, extra=e)
            ob = input(f"  Im Browser oeffnen? [j/N]: ").strip().lower()
            if ob == "j":
                q = urllib.parse.quote_plus(f'"{n}" {e}'.strip())
                webbrowser.open(f"https://www.google.com/search?q={q}")

        elif choice == "3":
            f = input(f"  {C.CYAN}Pfad zum Foto: {C.RESET}").strip().strip('"')
            if not Path(f).exists(): err(f"Datei nicht gefunden: {f}"); continue
            model = load_model(gpu=True)
            cmd_analyze(model, f)

        elif choice == "4":
            f = input(f"  {C.CYAN}Pfad zum Foto: {C.RESET}").strip().strip('"')
            if not Path(f).exists(): err(f"Datei nicht gefunden: {f}"); continue
            ob = input(f"  Im Browser oeffnen? [j/N]: ").strip().lower()
            model = load_model(gpu=True)
            cmd_social(model, f, open_browser=(ob == "j"))

        elif choice == "5":
            a = input(f"  {C.CYAN}Foto A (Ziel-Person): {C.RESET}").strip().strip('"')
            b = input(f"  {C.CYAN}Foto B (Vergleich):   {C.RESET}").strip().strip('"')
            for p in (a, b):
                if not Path(p).exists(): err(f"Datei nicht gefunden: {p}"); break
            else:
                model = load_model(gpu=True)
                cmd_compare(model, a, b)

        elif choice == "6":
            t = input(f"  {C.CYAN}Foto der Ziel-Person: {C.RESET}").strip().strip('"')
            d = input(f"  {C.CYAN}Ordner durchsuchen:   {C.RESET}").strip().strip('"')
            th = input(f"  Schwelle [0.0-1.0, Enter=0.45]: {C.RESET}").strip()
            th = float(th) if th else 0.45
            for p in (t, d):
                if not Path(p).exists(): err(f"Nicht gefunden: {p}"); break
            else:
                model = load_model(gpu=True)
                cmd_scan(model, t, d, th)
        else:
            warn("Ungueltige Auswahl.")

    info(f"Sitzung beendet in {time.time()-t0:.0f}s  |  Ergebnisse: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()