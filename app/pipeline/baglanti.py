"""Yeni zafiyetlerin saldırı grafiğine bağlanması (3. adım).

Dondurulmuş envanterdeki kayıtların hedefi, giriş noktası ve yetkinlikleri ekip
tarafından belirlendi. Envanterde olmayan yeni bir kayıt için üç katman sırayla denenir:

  1. Ekip kuralı: graph/generate_edges.py'deki CWE kümeleri (map_to_target). Dondurulmuş
     envanterle aynı mantık; tutarlılık için ilk sırada.
  2. MITRE CWE etkisi: inventory/cwe_etki.csv (tools/cwe_etki_tablosu.py). CWE'nin
     "Common Consequences" alanındaki en ağır teknik etki -> hedef.
  3. AI önerisi: yerel model (model v2 ile aynı Ollama modeli) kapalı listelerden hedef,
     giriş noktası, ön koşul ve kazanım seçer, gerekçesini yazar.
Son karar kullanıcınındır: 3. adımdaki tabloda her öneri değiştirilebilir. Hiçbir katmanın
bağlayamadığı kayıt "hedef belirsiz" olarak işaretlenir, sessizce kopuk kalmaz.

Seçilen hedef envanterin isteğe bağlı `hedef` sütununa yazılır; generate_edges.py bu sütun
doluysa onu kullanır. Dondurulmuş envanterde bu sütun yoktur, ekibin grafiği değişmez.
"""

import csv
import importlib.util
import json
import urllib.error
import urllib.request
from functools import lru_cache

from config import AI_DIR, GRAPH_DIR, OLLAMA_URL, REPO_ROOT

CWE_ETKI = REPO_ROOT / "inventory" / "cwe_etki.csv"
EK_SUTUNLAR = ["hedef", "hedef_kaynagi", "hedef_gerekcesi"]

HEDEFLER = {
    "node_target_admin": "Yönetici erişimi",
    "node_target_rce": "Kod çalıştırma",
    "node_target_account_takeover": "Hesap ele geçirme",
    "node_target_leak": "Veri sızıntısı",
    "node_target_dos": "Hizmet kesintisi",
}
GIRISLER = ["web", "api", "login", "search", "dependency"]
YETKINLIKLER = ["none", "admin_session", "password_hashes", "admin_credentials",
                "forged_identity", "stolen_session", "trusted_ip"]
KAYNAK_EKIP, KAYNAK_CWE, KAYNAK_AI, KAYNAK_ELLE = "ekip kuralı", "MITRE CWE etkisi", "AI önerisi", "elle"

# Model için hedeflerin anlamı (İngilizce: model v2 ile aynı dil)
_HEDEF_TANIM = {
    "node_target_admin": "attacker gains administrator access or administrator credentials",
    "node_target_rce": "attacker executes code or commands on the server, or compromises the system",
    "node_target_account_takeover": "attacker takes over another user's account or session (e.g. client-side attacks)",
    "node_target_leak": "attacker reads sensitive data, files or the database",
    "node_target_dos": "attacker makes the service unavailable or exhausts its resources",
}
_GIRIS_TANIM = {"web": "the web application pages", "api": "the REST API", "login": "the login form",
                "search": "the product search", "dependency": "a third-party package or the container image"}
_ORNEKLER = [   # dondurulmuş envanterden, ekibin kararlarıyla
    ("V001", {"target": "node_target_admin", "entry_point": "login", "requires_capability": "none",
              "grants_capability": "admin_session",
              "reason": "SQL injection in the login form bypasses authentication as the administrator."}),
    ("V025", {"target": "node_target_admin", "entry_point": "dependency", "requires_capability": "password_hashes",
              "grants_capability": "admin_credentials",
              "reason": "Weak password hashing lets stolen hashes be cracked into the administrator's password."}),
    ("V027", {"target": "node_target_rce", "entry_point": "dependency", "requires_capability": "none",
              "grants_capability": "none",
              "reason": "Archive extraction flaw in a dependency can write files outside the target folder and run code."}),
]


@lru_cache(maxsize=1)
def _cwe_tablosu():
    if not CWE_ETKI.exists():
        return {}
    with open(CWE_ETKI, encoding="utf-8") as f:
        return {r["cwe_id"].upper(): r for r in csv.DictReader(s for s in f if not s.startswith("#"))}


@lru_cache(maxsize=1)
def _ekip_kurali():
    spec = importlib.util.spec_from_file_location("generate_edges", GRAPH_DIR / "generate_edges.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.map_to_target


@lru_cache(maxsize=1)
def _model():
    spec = importlib.util.spec_from_file_location("residualmap_model_v2", AI_DIR / "model_v2_local_llm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cwe_bilgisi(cwe_id):
    return _cwe_tablosu().get((cwe_id or "").strip().upper())


def kural_onerisi(row):
    """1. ve 2. katman. Dönüş: {hedef, kaynak, gerekce, olasi} ya da hedef boş."""
    cwe = (row.get("cwe_id") or "").strip()
    ekip = _ekip_kurali()(row.get("vuln_id", ""), row.get("name", ""), cwe,
                          (row.get("grants_capability") or "none").strip().lower() or "none")
    if ekip:
        return {"hedef": ekip, "kaynak": KAYNAK_EKIP, "olasi": [ekip],
                "gerekce": f"{cwe or 'Ad'} ekibin CWE kümelerinde: {HEDEFLER[ekip].lower()} "
                           "(graph/generate_edges.py)."}
    bilgi = cwe_bilgisi(cwe)
    if bilgi and bilgi["hedef"]:
        olasi = [h for h in bilgi["olasi_hedefler"].split("; ") if h]
        ek = f" Diğer olası sonuçlar: {', '.join(HEDEFLER[h].lower() for h in olasi[1:])}." if len(olasi) > 1 else ""
        nereden = "" if bilgi["hedef_kaynagi"] == "kendi" else f" ({bilgi['hedef_kaynagi']} üzerinden)"
        return {"hedef": bilgi["hedef"], "kaynak": KAYNAK_CWE, "olasi": olasi,
                "gerekce": f"{cwe} ({bilgi['ad']}): MITRE'ye göre en ağır sonuç "
                           f"{HEDEFLER[bilgi['hedef']].lower()}{nereden}.{ek}"}
    neden = ("CWE yok" if not cwe else
             f"{cwe} için MITRE kataloğunda belirleyici bir teknik etki yok"
             + (f" ({bilgi['etkiler']})" if bilgi and bilgi["etkiler"] else ""))
    return {"hedef": "", "kaynak": "", "olasi": [], "gerekce": neden + "; AI önerisi ya da elle seçim gerekiyor."}


def onerileri_uygula(satirlar, yeni_idler):
    """Yeni kayıtlarda boş olan hedefi kural önerisiyle doldurur (yerinde). Elle ya da AI ile
    belirlenmiş hedeflere dokunmaz. Hedefi bulunamayanların listesini döndürür."""
    belirsiz = []
    for r in satirlar:
        if r["vuln_id"] not in yeni_idler or r.get("hedef"):
            continue
        o = kural_onerisi(r)
        r["hedef"], r["hedef_kaynagi"], r["hedef_gerekcesi"] = o["hedef"], o["kaynak"], o["gerekce"]
        if not o["hedef"]:
            belirsiz.append(r["vuln_id"])
    return belirsiz


# --- 3. katman: AI ---
def _prompt(r, envanter):
    m = _model()
    hedefler = "\n".join(f'- "{k}": {v}' for k, v in _HEDEF_TANIM.items())
    girisler = "\n".join(f'- "{k}": {v}' for k, v in _GIRIS_TANIM.items())
    ornekler = "\n\n".join(f"Example finding:\n{m.bulgu_metni(envanter[vid])}\nAnswer: {json.dumps(cevap)}"
                           for vid, cevap in _ORNEKLER if vid in envanter)
    ipucu = kural_onerisi(r)
    bilgi = cwe_bilgisi(r.get("cwe_id"))
    cwe_notu = (f"- MITRE CWE technical impacts for {r.get('cwe_id')}: {bilgi['etkiler'] or 'none listed'}"
                if bilgi else "- MITRE CWE technical impacts: not available")
    return f"""You are a security analyst building an attack graph for one OWASP Juice Shop instance.
Each finding must be connected to the attack graph: where the attacker starts, what the attacker
must already have, what the attacker gains, and which final target it leads to.

Targets (choose exactly one; use "none" only if the finding cannot plausibly lead to any of them):
{hedefler}

Entry points (choose exactly one):
{girisler}

Capabilities (closed list; use "none" when nothing special is required or gained):
{", ".join(f'"{c}"' for c in YETKINLIKLER)}
Most findings require and grant "none". Only use a capability when the finding clearly needs or yields it.

{ornekler}

Finding to connect:
{m.bulgu_metni(r)}
{cwe_notu}
- Rule-based suggestion: {HEDEFLER.get(ipucu['hedef'], 'none')} ({ipucu['gerekce']})

Return only JSON with exactly these keys:
{{"target": "...", "entry_point": "...", "requires_capability": "...", "grants_capability": "...",
"reason": "<at most 30 words: why this target>"}}"""


def _dogrula(icerik):
    veri = json.loads(icerik)
    anahtarlar = {"target", "entry_point", "requires_capability", "grants_capability", "reason"}
    if set(veri) != anahtarlar:
        raise ValueError(f"anahtarlar hatalı: {sorted(veri)}")
    if veri["target"] not in (*HEDEFLER, "none"):
        raise ValueError(f"hedef listede yok: {veri['target']}")
    if veri["entry_point"] not in GIRISLER:
        raise ValueError(f"giriş listede yok: {veri['entry_point']}")
    for k in ("requires_capability", "grants_capability"):
        if veri[k] not in YETKINLIKLER:
            raise ValueError(f"{k} listede yok: {veri[k]}")
    if not isinstance(veri["reason"], str) or not veri["reason"].strip():
        raise ValueError("gerekçe boş")
    return veri


def ai_onerisi(r, envanter, deneme=3, timeout=120):
    """Bir kayıt için model önerisi. Dönüş: dict ya da hata durumunda None ve hata metni."""
    m = _model()
    istek = json.dumps({"model": m.MODEL_NAME, "prompt": _prompt(r, envanter), "stream": False,
                        "format": "json", "options": m.OPTIONS}).encode("utf-8")
    hata = ""
    for _ in range(deneme):
        try:
            req = urllib.request.Request(f"{OLLAMA_URL}/api/generate", data=istek,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as yanit:
                govde = json.loads(yanit.read().decode("utf-8"))
            return _dogrula(govde["response"]), ""
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return None, f"Ollama'ya ulaşılamadı: {e}"
        except (ValueError, KeyError) as e:     # geçersiz JSON ya da kapalı liste dışı değer: yeniden sor
            hata = f"geçersiz yanıt: {e}"
    return None, hata


def ai_uygula(satir, oneri):
    """Model önerisini satıra yazar (yerinde)."""
    hedef = "" if oneri["target"] == "none" else oneri["target"]
    # Trivy kayıtları için giriş noktası kural gereği her zaman "dependency" (envanter.yeni_satir)
    giris = "dependency" if satir.get("cve_id") else oneri["entry_point"]
    satir.update({"hedef": hedef, "hedef_kaynagi": KAYNAK_AI,
                  "hedef_gerekcesi": f"{_model().MODEL_NAME}: {oneri['reason'].strip()}",
                  "entry_point": giris,
                  "requires_capability": oneri["requires_capability"],
                  "grants_capability": oneri["grants_capability"]})
