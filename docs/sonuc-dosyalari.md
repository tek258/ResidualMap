# Sonuç dosyaları

Rapordaki bütün sayılar bu dosyalardan gelir. `v-sonuclar` etiketinden sonra bu dosyalara dokunulmaz; hata bulunursa K1'e bildirilir ve düzeltme ayrı bir etiketle (`v-sonuclar-2`) yapılır.

Bu belge `python tools/sonuc_kontrol.py` ile üretilir. SHA-256 özetleri, metin dosyalarında satır sonları LF'ye çevrilerek hesaplanır; Windows ve Linux klonları aynı özeti verir.

## Dosyalar

| Dosya | İçerik | Üreten | Komut | Kayıt | SHA-256 |
|---|---|---|---|---|---|
| `inventory/inventory_v1.0.csv` | Dondurulmuş envanter | K2 (elle, S1) | `-` | 36 | `99335994113f7da4…` |
| `inventory/control_mapping.csv` | Kontrol eşlemesi (etki, dayanak, kanıt) | K2 (elle, S4-S5) | `-` | 36 | `2ffb7829f9befc8a…` |
| `inventory/after_controls.csv` | Kontroller açıkken durum | inventory/build_after_controls.py | `python inventory/build_after_controls.py` | 36 | `7ffb8017d7a8614e…` |
| `ai/results_v2_llm.csv` | AI risk skoru (risk_before) | ai/model_v2_local_llm.py | `python ai/model_v2_local_llm.py --tekrar-ids V001 V012 V035` | 36 | `134c568bc94611bc…` |
| `ai/residual_risk.csv` | Zafiyet düzeyinde artık risk | ai/residual_risk.py | `python ai/residual_risk.py` | 36 | `58a9a65a78624c85…` |
| `ai/before_after.csv` | Önce/sonra tablosu | ai/before_after.py | `python ai/before_after.py` | 36 | `bb7a4733fc4bf3bf…` |
| `graph/edges.json` | Saldırı grafiği kenarları | graph/generate_edges.py | `python graph/generate_edges.py` | 72 | `8ffab5f3deddac8f…` |
| `graph/paths.json` | Saldırı yolları ve riskleri | graph/find_paths.py | `python graph/find_paths.py` | 36 | `fa8ee4e998668b1e…` |
| `graph/edges_after.json` | Kontrol sonrası kenar durumları | graph/cut_edges.py | `python graph/cut_edges.py` | 72 | `bb75efbb9744c90d…` |
| `graph/paths_after.json` | Kontrol sonrası yol durumu ve riski | graph/paths_after.py | `python graph/paths_after.py` | 36 | `6517799f9b890740…` |
| `docs/once-sonra-ozet.md` | Önce/sonra özeti | ai/before_after.py | `python ai/before_after.py` | - | `8b350e99773cde56…` |
| `report/img/once-sonra.png` | Rapor grafiği | ai/before_after.py | `python ai/before_after.py` | - | `c006f38f8f50cb1e…` |
| `graph/attack_graph_v2.html` | Grafik (önce) | graph/visualize_graph.py | `python graph/visualize_graph.py` | - | `b00e3998cc06bbf4…` |
| `graph/attack_graph_after.html` | Grafik (sonra) | graph/visualize_graph.py | `python graph/visualize_graph.py --after` | - | `3ada1cc16f04f29c…` |
| `report/img/graf-once.png` | Rapor görseli | tarayıcı ekran görüntüsü | `attack_graph_v2.html, 1600×900, fizik yerleşimi durduktan sonra, ölçek 2` | - | `bdea64101715dfca…` |
| `report/img/graf-sonra.png` | Rapor görseli | tarayıcı ekran görüntüsü | `attack_graph_after.html, 1600×900, fizik yerleşimi durduktan sonra, ölçek 2` | - | `258256e376e4de70…` |
| `inventory/onlem_katalogu.csv` | Aday önlemler: etki, efor, kesinti, gerekçe | elle (ek savunma) | `-` | 15 | `c9afdf0fa016b3fe…` |
| `ai/onlem_tekil.csv` | Önlemler tek başına | ai/onlem_secimi.py | `python ai/onlem_secimi.py` | 15 | `74f712c599ccb121…` |
| `ai/onlem_secimi.json` | Bütçeye göre en iyi bileşim | ai/onlem_secimi.py | `python ai/onlem_secimi.py` | 4 | `89269720875f6825…` |
| `docs/onlem-secimi.md` | Önlem seçimi özeti | ai/onlem_secimi.py | `python ai/onlem_secimi.py` | - | `8a7e83831f01d72e…` |
| `report/img/onlem-butce.png` | Rapor grafiği | ai/onlem_secimi.py | `python ai/onlem_secimi.py` | - | `289525974c695192…` |

Tam özetler (`sha256sum` çıktısıyla karşılaştırmak için; satır sonları LF):

```
99335994113f7da4d6b9ca52f73c2f36b71c9b8516c45b723af686e7022cf6ec  inventory/inventory_v1.0.csv
2ffb7829f9befc8a624c3f1fce93cfb1eff4f9c962c617c6802d29d83c25638d  inventory/control_mapping.csv
7ffb8017d7a8614e3301fd2149d81d537e1e03f4ca932f8788ee81716d809004  inventory/after_controls.csv
134c568bc94611bc4fcac40c6405a8aec2488b776348cd80c9fb178566c1f211  ai/results_v2_llm.csv
58a9a65a78624c85497b246390ced14947dd3696270e11fb90e2f0e2d77f7b09  ai/residual_risk.csv
bb7a4733fc4bf3bfd2df560151a05d5331e0edee651358f27922452ec01c3b05  ai/before_after.csv
8ffab5f3deddac8fa86eb57346e668f3961d591250bfb9a149356bf51c1f5372  graph/edges.json
fa8ee4e998668b1e1c000d895b45a8a0b6b44f8e0f3efc1be3aa79b685c59cce  graph/paths.json
bb75efbb9744c90d5b59e0ea4c935f60cac57cc029f8e6e482658c68cce190b3  graph/edges_after.json
6517799f9b8907401be1b2252727c3c01a4acc47bc86a3dd45e11f6ebb00662b  graph/paths_after.json
8b350e99773cde566f2087eb46809d1564fd9367ca9924f13ac56e3cf8383cc9  docs/once-sonra-ozet.md
c006f38f8f50cb1e68aa159301c8cfa93695df05574cc432f0499c259e002f09  report/img/once-sonra.png
b00e3998cc06bbf4ca05350ab385dcfd7af90211cec476560d8bb679f45bf7d9  graph/attack_graph_v2.html
3ada1cc16f04f29ca25225f7252c998f7b44b1e9d27150ef7739dbc709b7665a  graph/attack_graph_after.html
bdea64101715dfca3d0d14c7589f0364174399a8a4f5be03065738d38cb5f242  report/img/graf-once.png
258256e376e4de707c2462f00d9de37f2da1b2409403e8a79c3097bee92e80b1  report/img/graf-sonra.png
c9afdf0fa016b3fecd566f62df19c44f793ef65d0d60a440423392bf7d54f80c  inventory/onlem_katalogu.csv
74f712c599ccb1219a82ed763ef485bdf07d6b0734c744605f5a41b0c1386d92  ai/onlem_tekil.csv
89269720875f6825af20152c201445365bab54cf8057b2113a0aafd242ada4cf  ai/onlem_secimi.json
8a7e83831f01d72ec4ba7fee7404fd0c1c063e6228749de09ff3fbc5e6f11125  docs/onlem-secimi.md
289525974c695192b76e72a079c155bfc5210c382ff0e844bc9f0ce5d97e4470  report/img/onlem-butce.png
```

## Yeniden üretim sırası

Bir girdi değişirse sonraki adımların hepsi yeniden çalıştırılır:

1. `python graph/generate_edges.py` → `python graph/find_paths.py`
2. `python inventory/build_after_controls.py`
3. `python ai/residual_risk.py`
4. `python graph/cut_edges.py` → `python graph/paths_after.py`
5. `python ai/before_after.py`
6. `python graph/visualize_graph.py` ve `python graph/visualize_graph.py --after`; PNG'ler tarayıcıdan 1600×900 pencerede, yerleşim durduktan sonra alınır
7. `python ai/onlem_secimi.py` (önlem kataloğu ya da residual_risk değişirse)
8. `python tools/sonuc_kontrol.py`

## Kontrol sonucu

- Zafiyet: engellendi 12, azaltildi 3; yol: kesildi 13, zayifladi 4, acik 19
- Toplam artık risk: 240.30 -> 163.33 (%32.03)
- Önlem seçimi: 15 aday, bütün önlemlerle (48 sa) yol riski 154.85 -> 64.34
- Tutarsızlık yok.
