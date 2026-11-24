"""CWE -> saldırı grafiği hedefi tablosu (inventory/cwe_etki.csv)

Yeni bir zafiyet dondurulmuş envanterde yoksa, grafikte hangi hedefe bağlanacağı
CWE'sinin MITRE kataloğundaki "Common Consequences" (teknik etki) alanından çıkarılır.
Bu betik katalogdan tabloyu üretir; uygulama yalnızca üretilen CSV'yi okur.

Kaynak: MITRE CWE v4.14 (cwec_v4.14.xml). PyPI'daki `cwe2` paketiyle birlikte gelir:
    pip download --no-deps cwe2   # .whl içinde cwe2/database_v49/cwec_v4.14.xml
Lisans: CWE, MITRE'nin kullanım koşullarıyla serbestçe kullanılabilir; telif notu
inventory/cwe_etki.csv'nin ilk satırında ve docs/yeni-zafiyet-baglama.md'de.

Etki -> hedef kuralı (sıra önemli: ilk tutan kazanır, en ağır sonuç önce):
    Execute Unauthorized Code or Commands      -> node_target_rce
    Gain Privileges or Assume Identity         -> node_target_admin
    Read Application Data / Read Memory /
      Read Files or Directories                -> node_target_leak
    DoS: ...                                   -> node_target_dos
Bunların hiçbiri yoksa (yalnızca "Bypass Protection Mechanism", "Modify ...",
"Varies by Context" gibi belirsiz etkiler ya da kategori CWE'leri) ve CWE'nin
üst CWE'leri (ChildOf, en fazla 3 seviye) de bir şey vermiyorsa hedef boş kalır:
o kayıt için AI önerisi ya da kullanıcı kararı gerekir.

Kullanım:
    python tools/cwe_etki_tablosu.py <cwec_v4.14.xml yolu>
"""

import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
CIKTI = KOK / "inventory" / "cwe_etki.csv"
NS = {"c": "http://cwe.mitre.org/cwe-7"}
KURALLAR = [
    ("node_target_rce", lambda i: i == "Execute Unauthorized Code or Commands"),
    ("node_target_admin", lambda i: i == "Gain Privileges or Assume Identity"),
    ("node_target_leak", lambda i: i in ("Read Application Data", "Read Memory", "Read Files or Directories")),
    ("node_target_dos", lambda i: i.startswith("DoS:")),
]
TELIF = ("# Kaynak: MITRE CWE v4.14 (Common Consequences). Copyright (c) 2006-2024, The MITRE "
         "Corporation. CWE ve CWE logosu MITRE'nin ticari markalarıdır.")


def hedefler_bul(etkiler):
    """Etkilerin işaret ettiği bütün hedefler, en ağırdan hafife."""
    return [h for h, kosul in KURALLAR if any(kosul(i) for i in etkiler)]


def hedef_bul(etkiler):
    h = hedefler_bul(etkiler)
    return h[0] if h else ""


def main(xml_yolu):
    kok = ET.parse(xml_yolu).getroot()
    kayit = {}
    for w in kok.findall(".//c:Weakness", NS):
        etkiler = []
        for i in w.findall("c:Common_Consequences/c:Consequence/c:Impact", NS):
            if i.text and i.text not in etkiler:
                etkiler.append(i.text)
        ustler = [r.get("CWE_ID") for r in w.findall("c:Related_Weaknesses/c:Related_Weakness", NS)
                  if r.get("Nature") == "ChildOf" and r.get("Ordinal", "Primary") == "Primary"]
        kayit[w.get("ID")] = {"ad": w.get("Name"), "etkiler": etkiler, "ustler": ustler}
    for c in kok.findall(".//c:Category", NS):          # kategorilerin teknik etkisi yok
        kayit.setdefault(c.get("ID"), {"ad": c.get("Name"), "etkiler": [], "ustler": []})

    satirlar = []
    for cid, k in sorted(kayit.items(), key=lambda x: int(x[0])):
        hedef, kaynak, ust_etki = hedef_bul(k["etkiler"]), "kendi" if k["etkiler"] else "", []
        if not hedef:                                       # üst CWE'lere bak (en fazla 3 seviye)
            sira, gorulen = list(k["ustler"]), set()
            for _ in range(3):
                sonraki = []
                for u in sira:
                    if u in gorulen or u not in kayit:
                        continue
                    gorulen.add(u)
                    h = hedef_bul(kayit[u]["etkiler"])
                    if h:
                        hedef, kaynak, ust_etki = h, f"üst CWE-{u}", kayit[u]["etkiler"]
                        break
                    sonraki += kayit[u]["ustler"]
                if hedef:
                    break
                sira = sonraki
        satirlar.append({"cwe_id": f"CWE-{cid}", "ad": k["ad"], "etkiler": "; ".join(k["etkiler"]),
                         "hedef": hedef, "olasi_hedefler": "; ".join(hedefler_bul(k["etkiler"] or ust_etki)),
                         "hedef_kaynagi": kaynak if hedef else ""})

    with open(CIKTI, "w", encoding="utf-8", newline="") as f:
        f.write(TELIF + "\n")
        w = csv.DictWriter(f, fieldnames=list(satirlar[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(satirlar)
    dolu = sum(1 for s in satirlar if s["hedef"])
    print(f"Yazıldı: {CIKTI.relative_to(KOK).as_posix()} ({len(satirlar)} CWE, {dolu} tanesine hedef bulundu)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
