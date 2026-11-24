"""5. ve 6. adım için çalıştırmaya özel önlem modeli.

ai/onlem_secimi.py'deki Model ekibin dondurulmuş 36 kaydıyla çalışır. Kullanıcı farklı bir seçim
yaptığında (örneğin bütün zafiyetler) 4. adımdaki grafik bu çalıştırmadan, 5. ve 6. adım ise
dondurulmuş sonuçlardan geliyordu. Bu modül aynı motoru (aynı formüller, aynı yöntemler) bu
çalıştırmanın dosyalarıyla kurar:

  yollar        runs/<id>/graph/paths.json ve inventory.csv (P_i: find_paths.py ile aynı)
  risk_before   bu çalıştırmanın AI skoru (ai_skorlari.csv); yoksa CVSS
  mevcut        ekibin kontrol eşlemesi (ai/residual_risk.csv, etkinlik). Eşlemesi olmayan yeni
                kayıtlar için 0: hiçbir kontrolün onu durdurduğu test edilmedi ya da gerekçelendirilmedi.
  katalog       ekibin önlem kataloğu (bu çalıştırmada olan zafiyetlerle) + yeni Trivy kayıtları için
                otomatik paket yükseltme önerileri (Trivy'deki düzeltilmiş sürümden):
                  - aynı paketi yükselten bir katalog önlemi varsa yeni CVE ona eklenir,
                  - işletim sistemi paketleri taban imaj güncellemesine eklenir,
                  - diğer paketler için "<paket> yükseltmesi (otomatik)" önlemi oluşturulur,
                  - düzeltilmiş sürümü olmayan CVE'ye önlem önerilmez.
Kesin arama bütün alt kümeleri dener; önlem sayısı büyükse (yollara dokunan önlem > KESIN_SINIR)
açgözlü seçime geçilir ve bu ekranda belirtilir.
"""

import csv
import importlib.util
import json
import math
import re
from pathlib import Path

from config import AI_DIR, FROZEN_INVENTORY, GRAPH_DIR, REPO_ROOT
from pipeline import ai_skor

KESIN_SINIR = 18
OTO_EFOR, OTO_EFOR_ANA = 2.0, 4.0


def motor_modulu():
    spec = importlib.util.spec_from_file_location("onlem_secimi", AI_DIR / "onlem_secimi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _csv(yol):
    if not Path(yol).exists():
        return []
    with open(yol, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _ana_surum(s):
    m = re.match(r"\D*(\d+)", s or "")
    return int(m.group(1)) if m else None


def _trivy_bilgisi(run_dir):
    """(cve, paket) -> {"sinif": os-pkgs/lang-pkgs, "kurulu": ..., "duzeltilmis": ...}"""
    yol = run_dir / "raw" / "trivy.json"
    if not yol.exists():
        yol = REPO_ROOT / "inventory" / "raw" / "trivy.json"
    if not yol.exists():
        return {}
    bilgi = {}
    for r in json.loads(yol.read_text(encoding="utf-8")).get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            k = (v["VulnerabilityID"], v["PkgName"])
            b = bilgi.setdefault(k, {"sinif": r.get("Class", ""), "kurulu": [], "duzeltilmis": ""})
            if v.get("InstalledVersion") not in b["kurulu"]:
                b["kurulu"].append(v.get("InstalledVersion"))
            b["duzeltilmis"] = b["duzeltilmis"] or (v.get("FixedVersion") or "")
    return bilgi


def kur(run_dir):
    """(motor modülü, model). Çalıştırmada envanter ve grafik yoksa ValueError."""
    run_dir = Path(run_dir)
    if not (run_dir / "inventory.csv").exists() or not (run_dir / "graph" / "paths.json").exists():
        raise ValueError("Bu çalıştırmada envanter ya da grafik yok.")
    mod = motor_modulu()

    class CalismaModeli(mod.Model):
        def __init__(self):     # noqa: D401 - ekibin __init__'i dondurulmuş dosyaları okur; burada çalıştırma
            fp = mod._find_paths()
            inv = _csv(run_dir / "inventory.csv")
            invd = {r["vuln_id"]: r for r in inv}
            donmus = {r["vuln_id"]: r for r in _csv(FROZEN_INVENTORY)}
            res = {r["vuln_id"]: r for r in _csv(mod.RESIDUAL)}
            ai = {r["vuln_id"]: _f(r.get("risk_score_llm")) for r in _csv(ai_skor.hazirla(run_dir))}

            # Dondurulmuş envanterle aynı kimlik, aynı ad: ekibin kontrol eşlemesi geçerli
            def donmus_mu(v):
                return v in res and v in donmus and donmus[v]["name"] == invd[v]["name"]

            self.risk_before, self.mevcut, self.kaynak = {}, {}, {}
            for v, r in invd.items():
                rb = ai.get(v)
                self.kaynak[v] = "AI skoru" if rb is not None else "CVSS"
                if rb is None:
                    rb = _f(r.get("cvss_score"))
                if rb is None:
                    rb, self.kaynak[v] = 5.0, "varsayılan (5.0)"
                self.risk_before[v] = rb
                self.mevcut[v] = float(res[v]["etkinlik"]) if donmus_mu(v) else 0.0
            self.kontroller = {v: res[v]["kontroller"] for v in invd if donmus_mu(v)}
            self.eslenmemis = [v for v in invd if not donmus_mu(v)]
            self.adlar = {v: r["name"] for v, r in invd.items()}

            olasilik = {v: fp.hesapla_cvss_probabilities(r.get("cvss_vector", "")) for v, r in invd.items()}
            self.yollar, self.risksiz_yol = [], 0
            for p in json.loads((run_dir / "graph" / "paths.json").read_text(encoding="utf-8")):
                zaf = [n for n in p["path"] if n.startswith("V")]
                if any(olasilik.get(v) is None for v in zaf):
                    self.risksiz_yol += 1
                    continue
                self.yollar.append({"yol": p["path"], "hedef": p["target"], "zafiyetler": zaf,
                                    "P": [olasilik[v] for v in zaf], "C": fp.TARGET_CRITICALITIES[p["target"]]})

            # --- katalog: ekibinki (bu çalıştırmadaki zafiyetlerle) + otomatik yükseltmeler ---
            self.katalog = []
            for r in _csv(mod.KATALOG):
                hedefler = [v for v in r["hedefler"].split(";") if v in invd and donmus_mu(v)]
                if hedefler:
                    self.katalog.append({**r, "hedefler": hedefler, "efor_saat": float(r["efor_saat"]), "oto": False})
            trivy = _trivy_bilgisi(run_dir)
            paket_onlemi = {}      # paket -> katalog önlemi
            os_onlemi = None
            for o in self.katalog:
                for v in o["hedefler"]:
                    pk = invd[v].get("component", "")
                    b = trivy.get((invd[v].get("cve_id"), pk), {})
                    if b.get("sinif") == "os-pkgs" and o["tur"] == "yama":
                        os_onlemi = os_onlemi or o
                    elif pk and o["tur"] == "yama":
                        paket_onlemi.setdefault(pk, o)
            self.duzeltmesiz, oto = [], {}
            for v in self.eslenmemis:
                r = invd[v]
                if not r.get("cve_id"):
                    continue
                pk = r.get("component", "")
                b = trivy.get((r["cve_id"], pk))
                if not b:
                    continue
                if not b["duzeltilmis"]:
                    self.duzeltmesiz.append(v)
                    continue
                if b["sinif"] == "os-pkgs" and os_onlemi:
                    os_onlemi["hedefler"].append(v)
                    os_onlemi["eklenen"] = os_onlemi.get("eklenen", 0) + 1
                elif pk in paket_onlemi:
                    paket_onlemi[pk]["hedefler"].append(v)
                    paket_onlemi[pk]["eklenen"] = paket_onlemi[pk].get("eklenen", 0) + 1
                else:
                    g = oto.setdefault(pk, {"hedefler": [], "kurulu": set(), "duzeltilmis": set(), "os": False})
                    g["hedefler"].append(v)
                    g["kurulu"].update(x for x in b["kurulu"] if x)
                    g["duzeltilmis"].update(x.strip() for x in b["duzeltilmis"].split(",") if x.strip())
                    g["os"] = g["os"] or b["sinif"] == "os-pkgs"
            for i, (pk, g) in enumerate(sorted(oto.items()), start=1):
                kurulu = sorted(g["kurulu"])
                hedef_surum = sorted(g["duzeltilmis"], key=lambda s: (_ana_surum(s) or 0, s))[-1]
                ana = (_ana_surum(hedef_surum) or 0) > max((_ana_surum(k) or 0) for k in kurulu) if kurulu else False
                self.katalog.append({
                    "onlem_id": f"O{i:02d}", "ad": f"{pk} yükseltmesi (otomatik)", "tur": "yama",
                    "hedefler": g["hedefler"], "etki": "engeller",
                    "efor_saat": OTO_EFOR_ANA if ana else OTO_EFOR, "kesinti": "dusuk", "oto": True,
                    "gerekce": (f"Otomatik öneri: Trivy'ye göre {pk} {' / '.join(kurulu)} → {hedef_surum} sürümünde "
                                f"düzeltilmiş ({len(g['hedefler'])} CVE). Efor varsayılan: "
                                + (f"{OTO_EFOR_ANA:g} saat (ana sürüm değişiyor)." if ana else f"{OTO_EFOR:g} saat.")
                                + " Ekip tarafından değerlendirilmedi."),
                })
            yollarda = {v for y in self.yollar for v in y["zafiyetler"]}
            self.yol_onlemleri = [o for o in self.katalog if set(o["hedefler"]) & yollarda]
            self.yontem = "kesin" if len(self.yol_onlemleri) <= KESIN_SINIR else "açgözlü"

        def en_iyi(self, butce, guven="gerekce", kesintisiz=False):
            if self.yontem == "açgözlü":
                return self.acgozlu(butce, guven, kesintisiz)
            # Yollara dokunmayan önlemler yol riskini değiştirmez: kesin arama yalnızca yol önlemleriyle
            tum, self.katalog = self.katalog, self.yol_onlemleri
            try:
                return super().en_iyi(butce, guven, kesintisiz)
            finally:
                self.katalog = tum

    return mod, CalismaModeli()


def senaryo_grafigi(mod, m, run_dir, onlem_idleri, guven, klasor, baslik, top_n=5):
    """ai/onlem_secimi.senaryo_grafigi ile aynı kurallar, bu çalıştırmanın kenar ve yollarıyla.
    onlem_idleri boşsa "bugün (kontroller açık)" grafiği olur. Dönüş: HTML dosyasının yolu."""
    run_dir, klasor = Path(run_dir), Path(klasor)
    klasor.mkdir(parents=True, exist_ok=True)
    etk = m.senaryo(onlem_idleri, guven)["etkinlik"]
    onlem_of = {}
    for o in m.katalog:
        if o["onlem_id"] in set(onlem_idleri):
            for v in o["hedefler"]:
                onlem_of.setdefault(v, []).append(o["onlem_id"])

    def kenar_zafiyeti(e):
        src, tgt = e["source"], e["target"]
        if src.startswith("node_entry_"):
            return tgt if not tgt.startswith("node_target_") else None
        return src if not src.startswith("node_target_") else None

    def durum(x):
        return "kesildi" if x >= mod.KESILDI_ESIK else ("zayifladi" if x > 0 else "acik")

    edges_file = run_dir / "graph" / "edges.json"
    kenarlar = []
    for e in json.loads(edges_file.read_text(encoding="utf-8")):
        v = kenar_zafiyeti(e)
        st = durum(etk.get(v, 0.0)) if v else "acik"
        kontrol = ", ".join(onlem_of.get(v, [])) or m.kontroller.get(v)
        kenarlar.append({**e, "status": st, "cutting_control": kontrol if st != "acik" else None})
    risk = {tuple(y["yol"]): y for y in m.yollar}
    yollar = []
    for p in json.loads((run_dir / "graph" / "paths.json").read_text(encoding="utf-8")):
        zaf = [n for n in p["path"] if n.startswith("V")]
        y = risk.get(tuple(p["path"]))
        r = round(math.prod(pi * (1 - etk.get(v, 0.0)) for pi, v in zip(y["P"], zaf)) * y["C"], 4) if y else None
        e = [etk.get(v, 0.0) for v in zaf]
        yollar.append({**p, "path_risk_after": r,
                       "status": "kesildi" if any(x >= mod.KESILDI_ESIK for x in e)
                       else ("zayifladi" if any(x > 0 for x in e) else "acik")})
    yollar.sort(key=lambda p: (p["path_risk_after"] is not None, p["path_risk_after"] or 0,
                               p.get("secondary_v2_score", 0)), reverse=True)
    (klasor / "edges_senaryo.json").write_text(json.dumps(kenarlar, ensure_ascii=False), encoding="utf-8")
    (klasor / "paths_senaryo.json").write_text(json.dumps(yollar, ensure_ascii=False), encoding="utf-8")
    with open(klasor / "residual_senaryo.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vuln_id", "risk_before", "risk_after", "etkinlik", "kontroller"])
        for v, rb in m.risk_before.items():
            w.writerow([v, rb, round(rb * (1 - etk.get(v, 0.0)), 4), round(etk.get(v, 0.0), 4),
                        ", ".join(onlem_of.get(v, [])) or m.kontroller.get(v) or "-"])
    with open(klasor / "durum_senaryo.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vuln_id", "durum"])
        for v in m.risk_before:
            w.writerow([v, {"kesildi": "kesildi", "zayifladi": "zayıfladı", "acik": "açık"}[durum(etk.get(v, 0.0))]])
    spec = importlib.util.spec_from_file_location("visualize_graph", GRAPH_DIR / "visualize_graph.py")
    vg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vg)
    ai_csv = str(ai_skor.hazirla(run_dir))      # renk ve hover bu çalıştırmanın AI skorlarından
    for ad in ("load_llm_results", "load_v2_results"):
        asil = getattr(vg, ad, None)
        if asil:
            setattr(vg, ad, lambda p=None, _a=asil: _a(p or ai_csv))
    html = klasor / "attack_graph_senaryo.html"
    vg.visualize_graph(edges_file=str(edges_file), output_html=str(html), csv_path=str(run_dir / "inventory.csv"),
                       edges_after_file=str(klasor / "edges_senaryo.json"),
                       paths_after_file=str(klasor / "paths_senaryo.json"),
                       residual_csv=str(klasor / "residual_senaryo.csv"),
                       after_csv=str(klasor / "durum_senaryo.csv"), baslik=baslik, top_n=top_n)
    return html
