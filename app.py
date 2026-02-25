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
# PLATFORM-DATENBANK  (Username → Profil-URL + Fehlerkennung)
# format: { "Name": {"url": "...", "err": "string_im_body_wenn_404", "code": 404} }
# "err"  = substring der NUR in der Fehlerseite vorkommt
# "code" = HTTP-Code der bei nicht existierendem Account kommt (default: 404)
# ─────────────────────────────────────────────────────────────────────────────
PLATFORMS: dict = {
    # ── Mainstream ──────────────────────────────────────────────────────────
    "Instagram":    {"url": "https://www.instagram.com/{}/",
                     "err": "Sorry, this page"},
    "TikTok":       {"url": "https://www.tiktok.com/@{}",
                     "err": "Couldn't find this account"},
    "Twitter/X":    {"url": "https://x.com/{}",
                     "err": "This account doesn"},
    "YouTube":      {"url": "https://www.youtube.com/@{}",
                     "err": "This page isn't available"},
    "Facebook":     {"url": "https://www.facebook.com/{}",
                     "code": 404},
    "Pinterest":    {"url": "https://www.pinterest.com/{}/",
                     "err": "isn't available"},
    "Snapchat":     {"url": "https://www.snapchat.com/add/{}",
                     "err": "Sorry! We couldn"},
    "Reddit":       {"url": "https://www.reddit.com/user/{}",
                     "err": "Sorry, nobody on Reddit"},
    "LinkedIn":     {"url": "https://www.linkedin.com/in/{}",
                     "code": 404},
    "Twitch":       {"url": "https://www.twitch.tv/{}",
                     "err": "Sorry. Unless you"},
    "BeReal":       {"url": "https://bere.al/{}",
                     "code": 404},
    "Tumblr":       {"url": "https://{}.tumblr.com/",
                     "err": "There's nothing here"},
    "Flickr":       {"url": "https://www.flickr.com/people/{}/",
                     "code": 404},
    "SoundCloud":   {"url": "https://soundcloud.com/{}",
                     "code": 404},
    "Spotify":      {"url": "https://open.spotify.com/user/{}",
                     "code": 404},
    # ── Dev / Tech ───────────────────────────────────────────────────────────
    "GitHub":       {"url": "https://github.com/{}",
                     "code": 404},
    "GitLab":       {"url": "https://gitlab.com/{}",
                     "code": 404},
    "Patreon":      {"url": "https://www.patreon.com/{}",
                     "code": 404},
    "Replit":       {"url": "https://replit.com/@{}",
                     "code": 404},
    "HackerNews":   {"url": "https://news.ycombinator.com/user?id={}",
                     "err": "No such user"},
    "Steam":        {"url": "https://steamcommunity.com/id/{}",
                     "err": "The specified profile could not be found"},
    # ── CIS / DACH / International ───────────────────────────────────────────
    "VK":           {"url": "https://vk.com/{}",
                     "err": "This page no longer exists"},
    "OK.ru":        {"url": "https://ok.ru/{}",
                     "code": 404},
    "XING":         {"url": "https://www.xing.com/profile/{}",
                     "code": 404},
    "Ask.fm":       {"url": "https://ask.fm/{}",
                     "code": 404},
    # ── Foren / Nischen ──────────────────────────────────────────────────────
    "Medium":       {"url": "https://medium.com/@{}",
                     "code": 404},
    "Substack":     {"url": "https://{}.substack.com/",
                     "code": 404},
    "Quora":        {"url": "https://www.quora.com/profile/{}",
                     "code": 404},
    "Wikipedia":    {"url": "https://en.wikipedia.org/wiki/User:{}",
                     "err": "does not exist"},
    "About.me":     {"url": "https://about.me/{}",
                     "code": 404},
    "Linktree":     {"url": "https://linktr.ee/{}",
                     "code": 404},
    "Behance":      {"url": "https://www.behance.net/{}",
                     "code": 404},
    "DeviantArt":   {"url": "https://www.deviantart.com/{}",
                     "code": 404},
    "500px":        {"url": "https://500px.com/p/{}",
                     "code": 404},
    "Vimeo":        {"url": "https://vimeo.com/{}",
                     "code": 404},
    "Dailymotion":  {"url": "https://www.dailymotion.com/{}",
                     "code": 404},
    "Twitch (clips)":{"url": "https://clips.twitch.tv/{}",
                     "code": 404},
    "Kick.com":     {"url": "https://kick.com/{}",
                     "code": 404},
    "Rumble":       {"url": "https://rumble.com/c/{}",
                     "code": 404},
    "Odysee":       {"url": "https://odysee.com/@{}",
                     "code": 404},
    "Mastodon":     {"url": "https://mastodon.social/@{}",
                     "code": 404},
    "Bluesky":      {"url": "https://bsky.app/profile/{}",
                     "code": 404},
    "Threads":      {"url": "https://www.threads.net/@{}",
                     "code": 404},
    "OnlyFans":     {"url": "https://onlyfans.com/{}",
                     "code": 404},
    "Fansly":       {"url": "https://fansly.com/{}",
                     "code": 404},
    "Vsco":         {"url": "https://vsco.co/{}",
                     "code": 404},
    "Poshmark":     {"url": "https://poshmark.com/closet/{}",
                     "code": 404},
    "Etsy":         {"url": "https://www.etsy.com/people/{}",
                     "code": 404},
    "Cashapp":      {"url": "https://cash.app/${}",
                     "code": 404},
    "Venmo":        {"url": "https://venmo.com/{}",
                     "code": 404},
    "Chess.com":    {"url": "https://www.chess.com/member/{}",
                     "code": 404},
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
    Gibt (name, url, found: bool, note: str) zurück.
    """
    url     = cfg["url"].format(username)
    err_str = cfg.get("err", None)
    exp_code= cfg.get("code", 404)
    try:
        if _REQUESTS_OK:
            r = _req.get(url, headers=_CHECK_HEADERS,
                         timeout=10, allow_redirects=True)
            code = r.status_code
            body = r.text
        else:
            req  = urllib.request.Request(url, headers=_CHECK_HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                code = resp.status
                body = resp.read(200).decode("utf-8", errors="ignore")

        if code == 200:
            if err_str and err_str.lower() in body.lower():
                return name, url, False, "Seite existiert, aber User nicht"
            return name, url, True, f"HTTP {code}"
        else:
            return name, url, False, f"HTTP {code}"
    except Exception as e:
        return name, url, None, f"Fehler: {e}"


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
def build_parser():
    p = argparse.ArgumentParser(
        description="OSINT Face Finder – KI-gestützte Gesichtssuche",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Beispiele:
  python app.py --analyze test.jpg
  python app.py --target oma.jpg --scan C:\\Fotos
  python app.py --target oma.jpg --compare bild2.jpg
  python app.py --target schwester.jpg --scan . --threshold 0.40 --cpu
  python app.py --username max_mustermann
  python app.py --social schwester.jpg
  python app.py --social schwester.jpg --open-browser
"""
    )
    p.add_argument("--analyze",      metavar="BILD",     help="Alle Gesichter in einem Bild analysieren")
    p.add_argument("--target",       metavar="BILD",     help="Referenz-Foto der gesuchten Person")
    p.add_argument("--scan",         metavar="ORDNER",   help="Ordner rekursiv nach Ziel-Person durchsuchen")
    p.add_argument("--compare",      metavar="BILD",     help="Einzelnes Bild mit Ziel-Person vergleichen")
    p.add_argument("--threshold",    metavar="0.0-1.0",  type=float, default=0.45,
                   help="Ähnlichkeits-Schwelle für --scan (Standard: 0.45)")
    p.add_argument("--username",     metavar="NAME",
                   help="Username auf 50+ Social-Media-Plattformen suchen")
    p.add_argument("--social",       metavar="BILD",
                   help="Gesicht aus Bild extrahieren + Social-Media-Suchlinks ausgeben")
    p.add_argument("--open-browser", action="store_true",
                   help="Bei --social: öffnet die wichtigsten Seiten direkt im Browser")
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
        parser.print_help()
        print(f"\n{C.YELLOW}[!]{C.RESET} Kein Modus angegeben. Schnell-Start:")
        print(f"    {C.CYAN}python app.py --analyze test.jpg{C.RESET}")
        print(f"    {C.CYAN}python app.py --target oma.jpg --scan .{C.RESET}\n")
        sys.exit(0)

    args = parser.parse_args()
    t0   = time.time()

    # ── Username-Modus braucht kein KI-Modell ────────────────────────────────
    if args.username:
        cmd_username(args.username)
        info(f"Fertig in {time.time() - t0:.1f}s  │  Ergebnisse in: {OUTPUT_DIR.resolve()}")
        return

    # ── Alle anderen Modi benötigen das KI-Modell ─────────────────────────────
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

if __name__ == "__main__":
    main()