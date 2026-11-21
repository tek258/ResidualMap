# Sonuç dosyaları

Rapordaki bütün sayılar bu dosyalardan gelir. `v-sonuclar` etiketinden sonra bu dosyalara dokunulmaz; hata bulunursa K1'e bildirilir ve düzeltme ayrı bir etiketle (`v-sonuclar-2`) yapılır.

Bu belge `python tools/sonuc_kontrol.py` ile üretilir. SHA-256 özetleri, metin dosyalarında satır sonları LF'ye çevrilerek hesaplanır; Windows ve Linux klonları aynı özeti verir.

## Dosyalar

| Dosya | İçerik | Üreten | Komut | Kayıt | SHA-256 |
|---|---|---|---|---|---|
| `inventory/inventory_v1.0.csv` | Dondurulmuş envanter | K2 (elle, S1) | `-` | 36 | `99335994113f7da4…` |
| `inventory/control_mapping.csv` | Kontrol eşlemesi (etki, dayanak, kanıt) | K2 (elle, S4-S5) | `-` | 36 | `4ee46b7a382cf104…` |
| `inventory/after_controls.csv` | Kontroller açıkken durum | inventory/build_after_controls.py | `python inventory/build_after_controls.py` | 36 | `2e88e30c5ba2c90c…` |
| `ai/results_v2_llm.csv` | AI risk skoru (risk_before) | ai/model_v2_local_llm.py | `python ai/model_v2_local_llm.py --tekrar-ids V001 V012 V035` | 36 | `134c568bc94611bc…` |
| `ai/residual_risk.csv` | Zafiyet düzeyinde artık risk | ai/residual_risk.py | `python ai/residual_risk.py` | 36 | `91aa3d08786beb51…` |
| `ai/before_after.csv` | Önce/sonra tablosu | ai/before_after.py | `python ai/before_after.py` | 36 | `5cad0a1d0367f82e…` |
| `graph/edges.json` | Saldırı grafiği kenarları | graph/generate_edges.py | `python graph/generate_edges.py` | 72 | `8ffab5f3deddac8f…` |
| `graph/paths.json` | Saldırı yolları ve riskleri | graph/find_paths.py | `python graph/find_paths.py` | 36 | `fa8ee4e998668b1e…` |
| `graph/edges_after.json` | Kontrol sonrası kenar durumları | graph/cut_edges.py | `python graph/cut_edges.py` | 72 | `a22088718388ed6f…` |
| `graph/paths_after.json` | Kontrol sonrası yol durumu ve riski | graph/paths_after.py | `python graph/paths_after.py` | 36 | `a6cc6e6139fe8c84…` |
| `docs/once-sonra-ozet.md` | Önce/sonra özeti | ai/before_after.py | `python ai/before_after.py` | - | `c08107a0dc3869c2…` |
| `report/img/once-sonra.png` | Rapor grafiği | ai/before_after.py | `python ai/before_after.py` | - | `73c4d16042879f7b…` |
| `graph/attack_graph_v2.html` | Grafik (önce) | graph/visualize_graph.py | `python graph/visualize_graph.py` | - | `490d9ec289f2b082…` |
| `graph/attack_graph_after.html` | Grafik (sonra) | graph/visualize_graph.py | `python graph/visualize_graph.py --after` | - | `2018aad9cfb29293…` |
| `report/img/graf-once.png` | Rapor görseli | tarayıcı ekran görüntüsü | `attack_graph_v2.html, 1600×1000, ölçek 2` | - | `f8ac3a090de6e8f5…` |
| `report/img/graf-sonra.png` | Rapor görseli | tarayıcı ekran görüntüsü | `attack_graph_after.html, 1600×1000, ölçek 2` | - | `0c51c24ada9d9d1b…` |

Tam özetler (`sha256sum` çıktısıyla karşılaştırmak için; satır sonları LF):

```
99335994113f7da4d6b9ca52f73c2f36b71c9b8516c45b723af686e7022cf6ec  inventory/inventory_v1.0.csv
4ee46b7a382cf10438e1ae7488d08ab1fb597669450b06b65215f16c7e5b62de  inventory/control_mapping.csv
2e88e30c5ba2c90c85048068d40f660d8a283b171ab85e8f2a67b8a2d5b813e3  inventory/after_controls.csv
134c568bc94611bc4fcac40c6405a8aec2488b776348cd80c9fb178566c1f211  ai/results_v2_llm.csv
91aa3d08786beb51040b98e6797dc8be693d3abd2ba0dc9c6d13cf9e6a79be1d  ai/residual_risk.csv
5cad0a1d0367f82e1eca4d65722e72fbe0d7ae59e4094f85a720c0ca2494c501  ai/before_after.csv
8ffab5f3deddac8fa86eb57346e668f3961d591250bfb9a149356bf51c1f5372  graph/edges.json
fa8ee4e998668b1e1c000d895b45a8a0b6b44f8e0f3efc1be3aa79b685c59cce  graph/paths.json
a22088718388ed6f3fe4dd0842c34015a9cf363782b6eb0dead0010bf9ae6f93  graph/edges_after.json
a6cc6e6139fe8c847edbc77d3ff55179946e16333e0cd8cd86b3bece79d0ebe3  graph/paths_after.json
c08107a0dc3869c20eadfc82a52f20fb337eb51be55952c71a58df2b03287370  docs/once-sonra-ozet.md
73c4d16042879f7b679491d0ed855efca56eb3ce41977f588b37f548aa759159  report/img/once-sonra.png
490d9ec289f2b08246e977754c71e0b3003cf72d4925bbaa9f63d55a5d0c0a00  graph/attack_graph_v2.html
2018aad9cfb29293ee9ada2835eaf7119dd8a9cc4238446d1d1e3e5fd360b1ef  graph/attack_graph_after.html
f8ac3a090de6e8f51f2f9818efb47c4b8b281954b27ba8cea83fb31cbecc1cf5  report/img/graf-once.png
0c51c24ada9d9d1b55312c19cee3966143ebc0b7e2a2f3fc7de74945ef64b0c0  report/img/graf-sonra.png
```

## Yeniden üretim sırası

Bir girdi değişirse sonraki adımların hepsi yeniden çalıştırılır:

1. `python graph/generate_edges.py` → `python graph/find_paths.py`
2. `python inventory/build_after_controls.py`
3. `python ai/residual_risk.py`
4. `python graph/cut_edges.py` → `python graph/paths_after.py`
5. `python ai/before_after.py`
6. `python graph/visualize_graph.py` ve `python graph/visualize_graph.py --after`; PNG'ler tarayıcıdan 1600×1000 pencerede alınır
7. `python tools/sonuc_kontrol.py`

## Kontrol sonucu

- Zafiyet: engellendi 4, azaltildi 2; yol: kesildi 4, zayifladi 6, acik 26
- Toplam artık risk: 240.30 -> 202.95 (%15.54)
- Tutarsızlık yok.
