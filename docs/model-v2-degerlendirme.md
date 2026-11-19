# Model v2 değerlendirmesi (S4-K4)

Bu not, v1'in hatalarını (`docs/model-v1-hata-analizi.md`) gidermek için yazılan model v2'yi; baseline, v1 ve iki kontrol çalıştırmasıyla karşılaştırır.

- **Betikler:**
  - `ai/model_v2_local_llm.py`
  - `ai/model_v1_qwen_kontrol.py`
  - `ai/v2_degerlendirme.py`
- **Sonuçlar:**
  - `ai/results_v2_llm.csv` (S5'te kullanılacak skor)
  - `ai/results_v1_qwen_llm.csv`
  - `ai/results_v2_nocvss_llm.csv`
  - `ai/v2_karsilastirma.csv`
- **Referans:** `ai/expert_labels.csv` (K2)

## 1. Özet

v2, uzman etiketleriyle sınıf uyumunda baseline'ı geçen ilk model: **24/33**. Baseline 19/33, v1 19/32.

- **CVSS'i kopyalamıyor:** Skoru CVSS'e eşit kayıt 5/33. v1'de bu sayı 31/32'ydi.
- **Kanıt ayrımını kullanıyor:** V001 ve V008'i Kritik'e çıkarıyor. CVSS'i 9'un üstünde olan bağımlılık bulgularını Yüksek'te tutuyor. Başlık bulgularını Düşük'e indiriyor.

Kontrol çalıştırması iyileşmenin kaynağını gösteriyor: daha büyük model biçim hatalarını giderdi, doğruluk artışı ise prompt tasarımından geldi.

Zayıf yan: v2 kayıtları doğru banda koyuyor ama bant içinde ayırt edemiyor. Spearman korelasyonu baseline'la neredeyse aynı (0.751 / 0.741).

## 2. Yöntem

### 2.1 v1'den v2'ye değişenler

| v1 hatası (hata analizi) | v2'deki karşılığı |
|---|---|
| Skor CVSS'in kopyası | Prompt'ta puanlama rubriği ve "CVSS bir girdidir, cevap değildir" talimatı |
| Etiket skorla çelişiyor (19 kayıt) | Modelden yalnızca skor isteniyor; sınıf kodda skordan türetiliyor (≥9 Kritik, ≥7 Yüksek, ≥4 Orta, <4 Düşük) |
| Kanıt türünü ayıramıyor | Kanıt türü ayrı bir alan: challenge ile doğrulanmış / Trivy paket eşleşmesi / ZAP gözlemi. Ayrıca bir öncelik kuralı var |
| EPSS yok sayılıyor | EPSS'in nasıl tartılacağı yazılı (>0.1 yüksek, <0.01 düşük) |
| Tarayıcı derecesi ve belirsizlik kullanılmıyor | Tarayıcının kendi derecesi, envanterdeki "emin değil" işareti, sömürülürse kazandırdığı yetki (`grants_capability`) ayrı alanlar olarak veriliyor |
| Örnek yok | 3 few-shot örneği: V023 (Yüksek), V006 (Orta), V019 (Düşük) |
| Biçim hataları sayılmıyor | Anahtarlar sıkı denetleniyor; yanlış anahtar adı geçersiz yanıt sayılıyor |
| Türkçe prompt, `temperature 0.1`, sınırsız çıktı | İngilizce prompt, `temperature 0`, `num_predict 400`, `seed 42` |
| `phi3:mini` | `qwen2.5:7b` |

En uzun prompt 1345 token. `num_ctx` 4096'ya çıkarıldı; Ollama'nın prompt'u sessizce kırpma riski yok.

### 2.2 Few-shot kayıtlarının ele alınışı

Örnek olarak kullanılan üç kayıt (V023, V006, V019) prompt'ta cevaplarıyla birlikte göründüğü için ana tablodan çıkarıldı. Ana tablo **33 kayıt** üzerinden hesaplandı. 36 kayıtlık tablo yalnızca bilgi için Ek A'da.

Bu üç kayıt `results_v2_llm.csv`'de yine de skorlu, çünkü grafik ve artık risk hesabı 36 kaydın hepsine skor istiyor. Hangi kaydın örnek olduğu `few_shot` sütununda işaretli.

### 2.3 Karşılaştırılan yöntemler

| Yöntem | Model | Prompt | Amaç |
|---|---|---|---|
| Baseline | — | — | `baseline_ranking.py`: yalnızca CVSS |
| v1 | phi3:mini | v1 (Türkçe, rubriksiz) | S2 sonucu |
| v1-qwen (kontrol) | qwen2.5:7b | v1, değiştirilmeden | Model değişikliğinin tek başına etkisi |
| v2 | qwen2.5:7b | v2 | Asıl model |
| v2 (sayısal CVSS yok) | qwen2.5:7b | v2, CVSS skoru çıkarılmış | Modelin CVSS sayısına bağımlılığı |

"Sayısal CVSS yok" varyantında CVSS skoru prompt'tan kaldırıldı. Vektörün sözel anlatımı, EPSS ve kanıt bilgisi duruyor; few-shot örnekleri de aynı biçimde gösterildi.

## 3. Sonuçlar

### 3.1 Karşılaştırma tablosu (33 kayıt, few-shot hariç)

| Yöntem | Skorlanan | Farklı skor | Skor = CVSS | Spearman | Sınıf doğruluğu | Baseline ile top-10 |
|---|---|---|---|---|---|---|
| Baseline (CVSS) | 33/33 | 15 | 33 | 0.741 | 19/33 (%57.6) | 10/10 |
| v1 (phi3) | 32/33 | 16 | 31 | **0.814** | 19/32 (%59.4) | 9/10 |
| v1-qwen (kontrol) | 33/33 | 16 | 21 | 0.674 | 18/33 (%54.5) | 10/10 |
| **v2** | 33/33 | 14 | 5 | 0.751 | **24/33 (%72.7)** | 5/10 |
| v2 (sayısal CVSS yok) | 33/33 | 16 | 0 | 0.688 | 22/33 (%66.7) | 6/10 |

- **Sınıf doğruluğu:** Skorun bandı (≥9 / ≥7 / ≥4) ile uzman etiketinin aynı olduğu kayıt sayısı. v1 ve v1-qwen'in modelden gelen kendi etiketleri bu tabloda değil: v1 13/35, v1-qwen 14/36.
- **v1'in Spearman değeri:** Görünüşte en yüksek, ama hata analizinde gösterildiği gibi bu, tekrarlanamayan V035 alan hatasından kaynaklanıyor.
- **Geçersiz yanıt:** Yalnızca v1'de var (V014 atlandı; tutarlılık testinde de 1/9). Diğer üç LLM çalıştırmasında geçersiz yanıt 0.

### 3.2 Sınıf dağılımı (33 kayıt)

| | Düşük | Orta | Yüksek | Kritik |
|---|---|---|---|---|
| Uzman | 6 | 9 | 16 | 2 |
| Baseline | 2 | 10 | 12 | 9 |
| v1-qwen | 1 | 9 | 14 | 9 |
| **v2** | 4 | 7 | 19 | 3 |
| v2 (CVSS yok) | 5 | 7 | 18 | 3 |

Baseline ve v1-qwen, uzmanın 2 Kritik'ine karşılık 9 kayda Kritik diyor. v2 bu fazlalığı 3'e indiriyor ve uzman dağılımına en çok yaklaşan yöntem oluyor.

### 3.3 Tutarlılık

| Kayıt | Tekrar skorları | std |
|---|---|---|
| V001 | 9.5, 9.5, 9.5 | 0.0 |
| V012 | 5.5, 5.5, 5.5 | 0.0 |
| V035 | 7.3, 7.3, 7.3 | 0.0 |

Tutarlılık testi v1'le aynı 3 kayıtla yapıldı. `temperature 0` ve sabit `seed` ile çıktının değişmemesi beklenen bir sonuç. Tekrarlanabilirlik sağlanıyor, ama bu doğruluk hakkında bir şey söylemiyor.

**Süre:** 36 kayıt + 6 ek tekrar = 42 çağrı, 130 sn (çağrı başına ~3 sn, GPU).

## 4. İyileşme nereden geliyor?

| Geçiş | Değişen | Sınıf doğruluğu | Yorum |
|---|---|---|---|
| v1 → v1-qwen | Yalnızca model | 19/32 → 18/33 | Doğruluk artmadı |
| v1-qwen → v2 | Yalnızca prompt | 18/33 → **24/33** | Artışın tamamı burada |

Model değişikliği doğruluğu artırmadı, ama biçimi belirgin şekilde düzeltti:
- geçersiz yanıt yok
- gerekçeler okunabilir; girdiyi tekrar etme, yarım kalma, uydurma CVE yok
- skorla çelişen etiket 19'dan 6'ya indi

v1 prompt'uyla qwen de CVSS'e yaslanıyor (21/33 kayıtta skor = CVSS) ve bağımlılık bulgularını Kritik'e taşıyor (V025–V028, V035, V036). Yani kanıt ayrımını model kendiliğinden yapmıyor; prompt açıkça istediğinde yapıyor.

## 5. Sayısal CVSS'siz çalıştırma

CVSS skoru kaldırılınca:
- Skor hiçbir kayıtta CVSS'e eşit değil (0/33).
- Sınıf doğruluğu 24/33'ten 22/33'e düştü, ama baseline'ın (19/33) hâlâ üstünde.

Model, CVSS sayısı olmadan da baseline'dan iyi bir sınıflandırma yapıyor. Yani v2'nin katkısı CVSS'i yeniden ölçeklemekten ibaret değil; kanıt türü ve vektör bilgisinden bağımsız bir değerlendirme var.

İki varyant farklı kayıtlarda yanılıyor:

| Kayıt | Uzman | v2 | v2 (CVSS yok) | Yorum |
|---|---|---|---|---|
| V022 | Yüksek | 9.3 Kritik | **7.8 Yüksek** | CVSS 9.8 görünmeyince "uydurma kanıt" hatası kayboldu |
| V018 | Düşük | 4.5 Orta | **3.8 Düşük** | |
| V009 | Yüksek | **7.5 Yüksek** | 5.5 Orta | Gerekçe "user interaction" diyor; vektörde UI:N |
| V015 | Yüksek | **7.9 Yüksek** | 9.2 Kritik | Yüksek karmaşıklık (brute force) dikkate alınmadı |
| V033, V034 | Yüksek | **Yüksek** | 4.3 Orta | DoS bulguları Orta'ya düştü |
| V003 | Orta | **6.8 Orta** | 7.0 Yüksek | Sınırda |

**Sonuç:** CVSS sayısı modele bant içinde yararlı bir sinyal veriyor. Sayı kaldırılınca yeni hatalar çıkıyor ve Spearman 0.751'den 0.688'e düşüyor. Ancak V022'de olduğu gibi, yüksek CVSS skoru modeli kanıt kuralını çiğnemeye de itebiliyor. S5'te kullanılacak skor için **v2 (CVSS'li)** öneriliyor.

## 6. Hata analizi (v2)

v2'nin uzmandan ayrıldığı 9 kayıt (33 içinde):

| Kayıt | CVSS | v2 | Uzman | Neden |
|---|---|---|---|---|
| V004 | 6.1 | 7.0 Yüksek | Orta | XSS; "birden çok kullanıcıyı etkileyebilir" diye yükseltmiş |
| V010 | 6.5 | 5.8 Orta | Yüksek | XXE; gerekçe V006 örneğinin kalıbını kopyalıyor ("needs a logged-in user and only exposes...") |
| V011 | 7.4 | 7.8 Yüksek | Orta | Yüksek karmaşıklık (OSINT) ve tek hesaba sınırlılık dikkate alınmadı |
| V012 | 4.3 | 5.5 Orta | Düşük | Sınırda; CSRF'nin etkisi sınırlı |
| V014 | 7.5 | 7.5 Yüksek | Orta | Uzman, açığa çıkan hesabın admin olduğu doğrulanmadığı için Orta diyor; bu bilgi modele verilmiyor |
| V018 | 3.1 | 4.5 Orta | Düşük | "Uncertain evidence" yazmış ama yine de Orta'ya çıkarmış |
| V022 | 9.8 | 9.3 Kritik | Yüksek | **Uydurma kanıt:** gerekçede "confirmed in the application" yazıyor, oysa Trivy bulgusu. "Kimlik token'ı sahteleme" bilgisi ve CVSS 9.8 ile Kritik'e çıkmış |
| V035 | 9.8 | 7.3 Yüksek | Orta | Tarayıcı derecesi MEDIUM ve kayıt "emin değil"; "move down" kuralı uygulanmamış |
| V036 | 9.8 | 7.8 Yüksek | Orta | Tarayıcı derecesi LOW ve kayıt "emin değil"; aynı kural uygulanmamış |

### Ortak kalıplar

1. **Bant içinde ayırt edememe.** 15 bağımlılık bulgusundan 14'ü 7.0–7.8 aralığında. EPSS'i en yüksek V024 (0.21) ile en düşük V028 (0.003) arasındaki fark yalnızca 0.5 puan. Bu yüzden Spearman baseline'ı geçemiyor ve en riskli yol sıralamasında eşitlikler oluşuyor.
2. **Gerekçede örnek kalıbını kopyalama.** 10 bağımlılık gerekçesi V023 örneğinin cümlesini neredeyse aynen kullanıyor. V020'nin gerekçesinde "version disclosure" geçiyor, ama bu bulgu tehlikeli JS fonksiyonuna ait; ifade V019 örneğinden gelmiş. CVSS'siz varyantta "version disclosure" ifadesi V017, V018 ve V020'nin gerekçelerinde de geçiyor. Gerekçeler v1'e göre çok daha tutarlı, ama kayda özgü değil.
3. **"Aşağı çek" kurallarının uygulanmaması.** Tarayıcı derecesi düşükse ya da kayıt belirsizse skoru düşürme kuralı V018, V035 ve V036'da işlememiş. Yukarı çeken sinyaller (yetki kazanımı, yüksek CVSS) aşağı çekenlerden daha etkili.
4. **Gerekçe ile skor çelişkisi (2 kayıt).** V003 ve V005'te gerekçe "High band" diyor, skor 6.8 (Orta). v1'deki 19 çelişkiye göre büyük düzelme.

## 7. Kabul kriterleri

| Kriter | Durum |
|---|---|
| Karşılaştırma tablosu var | ✅ Bölüm 3.1 |
| Few-shot kayıtlarının ele alınışı yazılı | ✅ Bölüm 2.2 |
| v2 uzman uyumunda baseline'ı geçiyor | ✅ 24/33 > 19/33 |

## 8. Sınırlılıklar

- **Rubrik uzman ölçütüne dayanıyor.** Rubrik, K2'nin etiketlemede kullandığı "Uzman Etiketleme Ölçütü"nden türetildi; few-shot skorları da uzman etiketinin bandında seçildi. Bu nedenle v2'nin yüksek uyumunun bir kısmı, modelin uzmanla aynı kuralı uygulamasından geliyor. Bu bir sızıntı değil (ölçüt etiketlemeden önce yazıldı ve prompt'ta yalnızca kurallar var, etiketler yok), ama v2'nin "uzmandan bağımsız bir görüş" olmadığı anlamına geliyor.
- **Veri küçük.** 33 kayıtta tek bir kaydın değişmesi doğruluğu ~3 puan oynatıyor. 24/33 ile 22/33 arasındaki fark anlamlı kabul edilmemeli.
- **Uzman etiketleri tek kişiye ait.** Etiketleyiciler arası uyum ölçülmedi.
- **Tutarlılık testi sınırlı.** 3 kayıtla yapıldı; `temperature 0` ile değişkenlik zaten beklenmiyor.
- **İkili karşılaştırma denenmedi.** "A mı B mi daha riskli?" yöntemi 33 kayıt için yüzlerce çağrı gerektirdiği ve S5'e etkisi olmayacağı için yapılmadı.

## 9. S5 için öneri

- Artık risk hesabında `ai/results_v2_llm.csv`'deki `risk_score_llm` kullanılsın. Karar K1 ile birlikte verilecek.
- Bant içi ayırt edicilik zayıf olduğu için yol sıralamasında eşitlikler görülebilir. Bu, raporda bir sınırlılık olarak belirtilmeli.
- Grafikte AI gerekçesi gösterilecekse kalıplaşmış oldukları belirtilmeli. Gösterilecek alan gerekçenin yalnızca ilk cümlesi olmalı.

## Ek A: 36 kayıt (few-shot dahil, yalnızca bilgi için)

| Yöntem | Skorlanan | Farklı skor | Skor = CVSS | Spearman | Sınıf doğruluğu | Baseline ile top-10 |
|---|---|---|---|---|---|---|
| Baseline | 36/36 | 15 | 36 | 0.768 | 20/36 (%55.6) | 10/10 |
| v1 (phi3) | 35/36 | 16 | 34 | 0.829 | 20/35 (%57.1) | 9/10 |
| v1-qwen | 36/36 | 16 | 23 | 0.707 | 20/36 (%55.6) | 10/10 |
| v2 | 36/36 | 16 | 5 | 0.775 | 27/36 (%75.0) | 5/10 |
| v2 (CVSS yok) | 36/36 | 18 | 0 | 0.720 | 25/36 (%69.4) | 5/10 |
