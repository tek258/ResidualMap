"""4. adım: repodaki graph/ scriptleriyle kenarları, yolları ve grafiği üretir.

Scriptler yeniden yazılmaz; graph/ klasöründen yüklenip çalıştırmanın kendi
envanteri ve çıktı klasörüyle çağrılır.
"""

import contextlib
import csv
import importlib.util
import io
import json
from collections import Counter

from config import GRAPH_DIR
from pipeline import ai_skor

HEDEF_ADLARI = {
    "node_target_admin": "Yetkisiz Admin Erişimi",
    "node_target_leak": "Hassas Veri Sızıntısı",
    "node_target_account_takeover": "Hesap Ele Geçirme",
    "node_target_rce": "RCE ve Sistem Ele Geçirme",
    "node_target_dos": "Hizmet Engelleme (DoS)",
}
CIKTILAR = {"edges": "edges.json", "paths": "paths.json", "html": "attack_graph.html"}


def _yukle(ad):
    """graph/<ad>.py'yi her seferinde diskten yükler (script değişirse güncel hali kullanılır)."""
    path = GRAPH_DIR / f"{ad}.py"
    if not path.exists():
        raise FileNotFoundError(f"{path} bulunamadı.")
    spec = importlib.util.spec_from_file_location(f"residualmap_{ad}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ai_kaynagini_yonlendir(fp, vg, ai_csv):
    """graph/ scriptleri AI skorlarını repodaki ai/results_v2_llm.csv'den okur. Uygulamada
    her çalıştırmanın kendi skorları var; scriptlere dokunmadan, yüklenen modüllerdeki okuma
    fonksiyonları bu çalıştırmanın skor dosyasına yönlendirilir."""
    with open(ai_csv, encoding="utf-8", newline="") as f:
        skorlar = {r["vuln_id"]: float(r["risk_score_llm"]) for r in csv.DictReader(f)}

    asil_fp = getattr(fp, "load_inventory_and_v2", None)
    if asil_fp:   # find_paths: yol sıralamasındaki eşitlik bozucu (secondary_v2_score)
        def _fp(csv_path=None):
            vuln_data, _ = asil_fp(csv_path)
            return vuln_data, skorlar
        fp.load_inventory_and_v2 = _fp

    for ad in ("load_llm_results", "load_v2_results"):   # visualize_graph: renk ve hover
        asil_vg = getattr(vg, ad, None)
        if asil_vg:
            setattr(vg, ad, lambda p=None, _a=asil_vg: _a(p or str(ai_csv)))
    return skorlar


def uret(inventory_csv, out_dir):
    """(ok, günlük metni) döndürür. Çıktılar out_dir altına yazılır."""
    out_dir.mkdir(parents=True, exist_ok=True)
    edges_p, paths_p, html_p = (out_dir / CIKTILAR[k] for k in ("edges", "paths", "html"))
    gunluk = io.StringIO()
    try:
        with contextlib.redirect_stdout(gunluk):
            fp, vg = _yukle("find_paths"), _yukle("visualize_graph")
            ai_csv = ai_skor.hazirla(inventory_csv.parent)
            skorlar = _ai_kaynagini_yonlendir(fp, vg, ai_csv)
            print(f"[AI] {len(skorlar)} kaydın AI skoru var ({ai_csv.name}).")
            edges = _yukle("generate_edges").generate_attack_edges(str(inventory_csv), str(edges_p))
            if edges is None:
                return False, gunluk.getvalue()
            # csv_path: yol olasılıkları bu çalıştırmanın envanterinden (repodakinden değil)
            paths = fp.find_attack_paths(str(edges_p), str(paths_p), str(inventory_csv))
            if paths is None:
                return False, gunluk.getvalue()
            # paths_path: grafikte bu çalıştırmanın en riskli yolları vurgulanır
            html = vg.create_visual_graph(
                str(edges_p), str(inventory_csv), str(html_p), str(paths_p))
            if html is None:
                return False, gunluk.getvalue()
    except Exception as e:   # ör. pyvis/networkx kurulu değil
        return False, gunluk.getvalue() + f"\n[HATA] {type(e).__name__}: {e}"
    return True, gunluk.getvalue()


def ozetle(inventory_csv, out_dir):
    """Üretilen grafiğin özeti: sayılar, hedef başına yol, zincirler, sorunlu kayıtlar."""
    with open(inventory_csv, encoding="utf-8", newline="") as f:
        satirlar = {r["vuln_id"]: r for r in csv.DictReader(f)}
    edges = json.loads((out_dir / CIKTILAR["edges"]).read_text(encoding="utf-8"))
    paths = json.loads((out_dir / CIKTILAR["paths"]).read_text(encoding="utf-8"))

    iliski = Counter(e["relation"] for e in edges)
    hedefli = {e["source"] for e in edges if e["relation"] == "Leads To"}
    girisli = {e["target"] for e in edges if e["relation"] == "Entry Point"}
    zincirli = {e["target"] for e in edges if e["relation"] == "Chains To"}
    yollarda = {n for p in paths for n in p["path"]}

    return {
        "zafiyet": len(satirlar),
        "kenar": len(edges),
        "iliski": dict(iliski),
        "yol": len(paths),
        "hedef_yol": {HEDEF_ADLARI.get(h, h): n
                      for h, n in Counter(p["target"] for p in paths).most_common()},
        "zincirler": [{"kaynak": e["source"], "hedef": e["target"], "aciklama": e["technique_name"]}
                      for e in edges if e["relation"] == "Chains To"],
        "zincirli_yollar": [" → ".join(p["path"]) for p in paths if p["length"] > 2],
        # hiçbir hedefe bağlanamayan (CWE kümelerinde yok)
        "hedefsiz": [v for v in satirlar if v not in hedefli],
        # ön koşulu yok ama giriş kenarı da yok: entry_point boş ya da liste dışı
        "girissiz": [v for v, r in satirlar.items()
                     if (r.get("requires_capability") or "none").strip().lower() == "none"
                     and v not in girisli],
        # CVSS vektörü eksik olduğu için riski hesaplanamayan yollar
        "risksiz_yollar": [" → ".join(p["path"]) for p in paths if p.get("path_risk") is None],
        # doğrudan girişi yok, sadece zincirle ulaşılıyor
        "sadece_zincirle": sorted(zincirli - girisli),
        # hiçbir yolda yer almayan (ne girişten ne zincirle ulaşılabiliyor)
        "ulasilamayan": [v for v in satirlar if v not in yollarda],
        "adlar": {v: r["name"] for v, r in satirlar.items()},
    }
