# Ölçüm metodolojisi: artık risk (S5-K1)

**Durum:** K1 onayladı (18.11.2026). Ekip itiraz süresi: 20.11.2026 akşamı; itiraz yoksa kesinleşir.
**Kullananlar:** K4 `ai/residual_risk.py` (S5-K4) · K3 `graph/cut_edges.py` (S5-K3) · K2 `inventory/after_controls.csv` (S6-K2) · rapor
**Girdiler:** `inventory/inventory_v1.0.csv`, `inventory/control_mapping.csv` (S4-K2), `ai/results_v2_llm.csv` (S4-K4)

Bu belge tek bir soruya cevap veriyor: **Kontroller devreye girdikten sonra her zafiyetin ve her saldırı yolunun riski ne kadar kaldı?** Rapordaki bütün önce/sonra sayıları bu tanımdan üretilir. Tanım değişirse sayılar da değişir; o yüzden sonuçlar dondurulduktan sonra (24.11.2026) bu belge değişmez.

---

## 1. Önceki risk (`risk_before`)

Her zafiyet için 0–10 arasında bir sayı.

**Karar:** `risk_before` = **model v2 skoru** (`ai/results_v2_llm.csv`, `risk_score_llm`).

**Yedek kural:** v2, değerlendirmede (S4-K4) uzman etiketleriyle v1'den ya da baseline'dan daha düşük uyum gösterirse, en yüksek uyumu gösteren skor kullanılır. Hangi skorun seçildiği ve gerekçesi `docs/model-v2-degerlendirme.md`'ye ve bu belgenin 8. bölümüne yazılır. Seçim bir kez yapılır; sonuçlara bakıp skor değiştirilmez.

**Neden CVSS değil:** CVSS zafiyetin teorik ciddiyetini ölçer; erişilebilirliği (`entry_point`), sömürülme olasılığını (EPSS) ve varlık kritikliğini birlikte tartmaz. Projenin iddiası, modelin bu bilgileri birleştirerek daha isabetli bir öncelik verdiği. Artık riski de aynı skordan hesaplamak bu iddiayla tutarlı.

## 2. Kontrol etkinliği

Bir kontrolün bir zafiyete karşı etkinliği iki şeyin çarpımı: **etki ne kadar** ve **bundan ne kadar eminiz**.

```
etkinlik = etki_değeri × güven_çarpanı
```

| Etki (`control_mapping.csv`) | Etki değeri | Anlamı |
|---|---|---|
| `engeller` | 0.9 | Saldırı isteği uygulamaya ulaşmıyor |
| `azaltir` | 0.5 | Kısmen engelliyor ya da sömürüyü zorlaştırıyor (ör. tam eşikte engelleme, bant dışı sızıntının kapanması) |
| `tespit_eder` | 0.2 | Saldırı geçiyor ama alarm üretiyor; müdahale süresini kısaltıyor |
| `etkisiz` | 0.0 | Kontrolün bu zafiyete etkisi yok |

| Dayanak | Güven çarpanı | Anlamı |
|---|---|---|
| `test` | 1.0 | Lab'da saldırı denendi, sonuç kaydedildi (ör. `test-waf.sh`, `test-iam.py`) |
| `gerekce` | 0.7 | Test edilmedi; mekanizma belgelenmiş bir gerekçeyle açıklanıyor |
| `varsayim` | — | **Hesaba katılmaz.** Kayıt ayrı bir bayrakla raporlanır (Bölüm 6) |

Sonuç tablosu (K4 bu tabloyu koda sözlük olarak koyar):

| | test | gerekce |
|---|---|---|
| engeller | **0.90** | 0.63 |
| azaltir | **0.50** | 0.35 |
| tespit_eder | 0.20 | 0.14 |
| etkisiz | 0.00 | 0.00 |

**Neden 1.0 değil 0.9:** Hiçbir kontrol bütün saldırı varyasyonlarını kapsamaz. Testler belirli yükleri dener; başka bir yazılış geçebilir. 0.9 bu belirsizliği temsil ediyor.

**Neden azaltır = 0.5:** V001 ve V002 testte 403 aldı, ama tek bir kuralla ve puan tam eşikte (5). Eşik 6'ya çıkarılırsa ya da yük biraz değiştirilirse geçebilirler. "Engelledi" demek bu kırılganlığı gizler; 0.5 "çoğu durumda engeller ama güvenilmez" demek.

**Önemli:** Bu değerler **ölçülmüş değil, atanmış**. Raporda bunu açıkça söyleriz ve sonuçların bu değerlere ne kadar duyarlı olduğunu gösteririz (Bölüm 7).

## 3. Birden fazla kontrol

Bir zafiyete birden fazla kontrol etki ediyorsa kontrollerin bağımsız çalıştığı varsayılır:

```
toplam_etkinlik = 1 − Π (1 − etkinlik_i)
```

Örnek: WAF `azaltir/test` (0.5) ve IDS `tespit_eder/gerekce` (0.14) → 1 − (0.5 × 0.86) = **0.57**. İki kontrol birlikte tek başına herhangi birinden daha etkili, ama etkileri basitçe toplanmıyor (toplasaydık 0.64 olurdu ve birden fazla kontrolle 1'i aşabilirdi).

**Varsayımın sınırı:** Gerçekte kontroller bağımsız değil. Örneğin WAF'ın engellediği isteği IDS de görüyor ama artık önemi yok. Bağımsızlık varsayımı toplam etkinliği biraz fazla gösterebilir; raporda sınırlılık olarak yazılır.

## 4. Zafiyet seviyesinde artık risk

```
risk_after = risk_before × (1 − toplam_etkinlik)
```

`risk_after` da 0–10 arasında. Kontrolü olmayan ya da yalnızca `etkisiz` kontrolü olan zafiyette `risk_after = risk_before`.

### Elle hesaplanmış örnekler

K4 bu üç örneği birim testi olarak yazar (`ai/test_residual_risk.py`). Burada `risk_before` yerine **CVSS** kullanıldı, çünkü v2 skorları henüz hazır değil; v2 gelince sayılar değişir, yöntem ve beklenen oranlar değişmez.

| | V001 (login SQLi) | V009 (/ftp gizli belge) | V022 (jsonwebtoken) |
|---|---|---|---|
| `risk_before` (örnek: CVSS) | 9.8 | 7.5 | 9.8 |
| Kontrol | WAF | IAM | WAF |
| Etki / dayanak | `azaltir` / `test` | `engeller` / `test` | `etkisiz` / `test`* |
| Etkinlik | 0.5 × 1.0 = 0.50 | 0.9 × 1.0 = 0.90 | 0.0 |
| `risk_after` | 9.8 × 0.50 = **4.90** | 7.5 × 0.10 = **0.75** | 9.8 × 1.00 = **9.80** |
| Yorum | Azaldı ama hâlâ yüksek: tam eşikte engelleme güvenilmez | Neredeyse sıfır: girişsiz ve rolsüz erişim testte engellendi | Değişmedi: WAF kütüphane zafiyetini görmez, yama uygulanmadı |

\* V022'nin dayanağı K2'nin tablosuna göre `gerekce` de olabilir; `etkisiz` olduğu için sonuç değişmez.

Bu üç örnek projenin üç ana bulgusunu temsil ediyor: kontroller bazı riskleri neredeyse sıfırlıyor (V009), bazılarını yalnızca azaltıyor (V001), bazılarına hiç dokunmuyor (V022).

## 5. Yol seviyesinde artık risk

Saldırı grafiğindeki her yol (`graph/paths.json`) için:

1. **Yol riski:** K3'ün S2'de seçtiği yöntemle (`docs/yol-risk-yontemi.md`) hesaplanır. Önce/sonra karşılaştırması için aynı yöntem iki kez uygulanır: bir kez `risk_before`, bir kez `risk_after` değerleriyle. Yöntem değiştirilmez, yalnızca girdi değişir.
2. **Yol durumu** (K3, `cut_edges.py`):
   - **kesildi:** yoldaki en az bir zafiyetin toplam etkinliği ≥ 0.9 (pratikte: `engeller` + `test`)
   - **zayifladi:** kesilmedi ama yoldaki en az bir zafiyetin toplam etkinliği > 0
   - **acik:** yoldaki hiçbir zafiyete etkili bir kontrol yok

**Zincirler:** Yolların çoğu tek zafiyetten oluşuyor (giriş → zafiyet → hedef). Tek gerçek zincir V002 → V025. Zincirin ilk halkası kesilirse sonraki halkaya o yoldan ulaşılamaz; zincir yolu "kesildi" sayılır. V025'e başka bir yoldan (doğrudan `dependency` girişinden) ulaşılabiliyorsa o yol ayrıca değerlendirilir.

## 6. Raporlanacak sayılar

K4 (`before_after.csv`, S6) ve rapor aşağıdaki sayıları üretir. **Her biri iki kez verilir:** bütün kayıtlar için ve yalnızca `dayanak = test` olan kayıtlar için. Asıl güvenilir sonuç ikincisi.

| Sayı | Tanım |
|---|---|
| Toplam risk düşüşü | Σ `risk_before` − Σ `risk_after`, ve yüzdesi |
| Ortalama risk düşüşü | kayıt başına ortalama `risk_before − risk_after` |
| Kaynak türüne göre düşüş | Juice Shop challenge / ZAP / Trivy (kütüphane) ayrı ayrı |
| Durum dağılımı | `after_controls.csv`'deki engellendi / azaltıldı / tespit edildi / erişilebilir / test edilmedi sayıları |
| Yol durumu | kesildi / zayıfladı / açık yol sayıları, hedef düğümüne göre |
| En çok düşen 5 ve hiç düşmeyen kayıtlar | her biri için bir cümlelik açıklama |

**Hesaba katılmayan kayıtlar:** `dayanak = varsayim` olan eşlemeler hesapta yok sayılır (o kontrol yokmuş gibi). Bu kayıtların sayısı ve listesi raporda ayrı bir satırda verilir. Böylece kanıtsız iddialar sonucu şişirmez, ama gizlenmiş de olmaz.

## 7. Duyarlılık analizi

Etkinlik değerleri atandığı için sonuçların bu değerlere ne kadar bağlı olduğu gösterilmeli (K4, S5):

- Etki değerleri (0.9, 0.5, 0.2) **±0.1** değiştirildiğinde:
  - toplam risk düşüşü yüzdesi ne kadar değişiyor?
  - en riskli 10 kaydın sıralaması ne kadar değişiyor (kaç kayıt listeye girip çıkıyor)?
- Güven çarpanı (`gerekce` = 0.7) 0.5 ve 0.9 yapıldığında aynı iki soru.

Sonuç bir paragraf ve küçük bir tabloyla rapora girer. Sıralama az değişiyorsa "sonuçlar atanan değerlere duyarlı değil" diyebiliriz; çok değişiyorsa bunu sınırlılık olarak açıkça yazarız.

## 8. Kararlar ve onay

| # | Karar | Durum |
|---|---|---|
| 1 | `risk_before` = model v2 skoru (yedek kural: en yüksek uyumlu skor) | Onaylandı (K1, 18.11.2026) |
| 2 | Etkinlik = etki değeri × güven çarpanı; değerler Bölüm 2'deki tablo | Onaylandı (K1, 18.11.2026) |
| 3 | Birden fazla kontrol: `1 − Π(1 − e_i)` | Onaylandı (K1, 18.11.2026) |
| 4 | `varsayim` dayanaklı eşlemeler hesaba katılmaz, ayrı raporlanır | Onaylandı (K1, 18.11.2026) |
| 5 | Yol riski K3'ün mevcut yöntemiyle; "kesildi" eşiği toplam etkinlik ≥ 0.9 | Onaylandı (K1, 18.11.2026) |

**Seçilen `risk_before` skoru (S4-K4 sonrası doldurulacak):** <!-- v2 / v1 / baseline ve gerekçe -->

## 9. Sınırlılıklar (rapora girecek)

- **Etkinlik değerleri atanmış, ölçülmemiş.** Duyarlılık analiziyle desteklenir ama gerçek bir saldırı istatistiğine dayanmaz.
- **Testler sınırlı.** Her zafiyet için birkaç yük denendi; "test" dayanağı "her varyasyon engellenir" anlamına gelmez (bu yüzden 0.9).
- **Kontrollerin bağımsızlığı varsayıldı** (Bölüm 3).
- **Risk skorları modelden geliyor.** Modelin hataları artık riske de taşınır; model değerlendirmesi (S4-K4) bu yüzden önemli.
- **Küçük örneklem.** 36 kayıt; yüzdeler birkaç kaydın değişmesiyle belirgin biçimde oynayabilir.
- **Yalnızca bir anlık görüntü.** Sonuçlar 24.11.2026'da dondurulan lab yapılandırmasını yansıtır.
