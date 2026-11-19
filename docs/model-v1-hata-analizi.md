# Model v1 hata analizi (S3-K4)

Bu not, model v1'in (`ai/model_v1_local_llm.py`, `phi3:mini`) uzman etiketlerinden nerede ve neden ayrıldığını inceler. Amaç, v2'de neyin değişmesi gerektiğini kanıta dayandırmaktır.

- **Girdiler:** `ai/results_v1_llm.csv` (v1 sonuçları), `ai/expert_labels.csv` (K2), `ai/features.csv`
- **Betikler:** `ai/v1_hata_analizi.py` (karşılaştırma, Ollama gerekmez), `ai/v1_tutarlilik.py` (tekrar testi)
- **Çıktılar:** `ai/v1_karsilastirma.csv`, `ai/v1_tutarlilik.csv`
- **Model:** `phi3:mini` (Ollama ID `4f2222927938`; tutarlılık testinde aynı modelin `phi3:3.8b` etiketi kullanıldı), `temperature 0.1`, `num_ctx 2048`, Türkçe prompt

## 1. Özet

v1 CVSS-only yöntemden daha iyi bir önceliklendirme üretmiyor:

- Skor 35 kaydın 34'ünde CVSS'in birebir kopyası.
- Etiket büyük ölçüde sabit: 35 kaydın 30'u "Yüksek".
- CVSS skorunu doğrudan sınıfa çeviren basit yöntem uzmanla 20/35 uyuşuyor, v1 13/35.

Model tutarlı, ama tutarlı biçimde yanlış: aynı kaydı tekrar çalıştırınca aynı skoru ve aynı etiketi veriyor.

## 2. Uzman etiketleriyle karşılaştırma

V014 v1'de Ollama 500 hatası nedeniyle atlandığı için karşılaştırma 35 kayıt üzerindedir.

| Yöntem | Uzmanla aynı sınıf | Spearman (uzman sırası) |
|---|---|---|
| v1 etiketi | 13/35 (%37.1) | 0.283 |
| v1 skoru | — | 0.829 |
| Baseline: CVSS bandı (≥9 Kritik, ≥7 Yüksek, ≥4 Orta, <4 Düşük) | **20/35 (%57.1)** | 0.775 |

Baseline, `ai/baseline_ranking.py`'ın sıralamasıdır: yalnızca CVSS'e göre sıralar, yani `baseline_score` = CVSS. Uzman etiketiyle sınıf düzeyinde karşılaştırabilmek için bu skor, CVSS v3.1'in önem bantlarıyla sınıfa çevrildi.

**Top-10 karşılaştırması:** v1'in en yüksek 10 skoru ile baseline'ın top-10'u 9/10 örtüşüyor. Tek fark, v1'de V035'in yerine V029'un girmesi; bunun nedeni de V035'teki alan hatası (bkz. Bölüm 3, K6). Uzmanın Kritik dediği iki kayıt (V001, V008) iki listede de var. Bu yüzden top-10 düzeyinde v1 baseline'dan ayırt edilemiyor.

v1 skorunun Spearman değeri CVSS'ten yüksek görünüyor. Ama iki skor yalnızca V035'te farklı: model o kayıtta skor alanına EPSS'i (0.00718) yazmış. Uzman da V035'i düşük tuttuğu (Orta) için bu hata korelasyonu tesadüfen yükseltmiş. Tutarlılık testinde V035 artık 9.8 alıyor (Bölüm 4), yani bu üstünlük tekrarlanamıyor.

v1 değerlendirmesindeki "baseline ile top-10 örtüşmesi %90" sonucu da bir başarı göstergesi değil: skor CVSS'in kopyası olduğu için örtüşme kaçınılmaz.

### Karışıklık matrisi

Satırlar uzman etiketini, sütunlar v1 etiketini gösterir.

| Uzman \ v1 | Kritik | Yüksek | Orta | Düşük | Toplam |
|---|---|---|---|---|---|
| Kritik | 0 | 2 | 0 | 0 | 2 |
| Yüksek | 4 | **13** | 0 | 0 | 17 |
| Orta | 0 | 8 | 0 | 1 | 9 |
| Düşük | 0 | 7 | 0 | 0 | 7 |
| **Toplam** | 4 | 30 | 0 | 1 | 35 |

13 doğru sınıflandırmanın tamamı "Yüksek" sütununda. Model başka hiçbir sınıfı doğru tutturmuyor. Sapmaların 28/35'i en fazla bir sınıflık; ama bu, uzman dağılımının da ortada yoğunlaşmasından kaynaklanıyor.

## 3. Uyuşmayan kayıtlar ve hata kalıpları

22 kayıt uyuşmuyor: 19'unda v1 riski fazla, 3'ünde eksik veriyor (V001, V008, V035).

### K1: Etiketin "Yüksek"e yığılması (15 kayıt)

| Kayıt | CVSS | Uzman | v1 |
|---|---|---|---|
| V003, V004, V005 (XSS) | 6.1 | Orta | Yüksek |
| V006, V007 (IDOR) | 6.5 | Orta | Yüksek |
| V011 (şifre sıfırlama) | 7.4 | Orta | Yüksek |
| V013 (açık yönlendirme) | 6.1 | Orta | Yüksek |
| V036 (libc6, bağımlılık) | 9.8 | Orta | Yüksek |
| V012 (CSRF) | 4.3 | Düşük | Yüksek |
| V016 (hata mesajı) | 5.3 | Düşük | Yüksek |
| V017 (CSP) | 4.2 | Düşük | Yüksek |
| V018 (CORS) | 3.1 | Düşük | Yüksek |
| V019 (sürüm sızıntısı) | 5.3 | Düşük | Yüksek |
| V020 (tehlikeli JS) | 4.2 | Düşük | Yüksek |
| V021 (COOP/COEP) | 3.1 | Düşük | Yüksek |

V036 dışındakilerin hepsi uygulama bulgusu. Model, ZAP'ın "Low" dediği başlık bulgularına bile "Yüksek" veriyor. Bu yüzden uygulama bulgularında uyum yalnızca 4/20.

### K2: Etiketin kendi skoruyla çelişmesi (19 kayıt)

Model skoru ve etiketi ayrı ayrı üretiyor ve ikisi birbirini tutmuyor. Örnekler:

- V018: skor 3.1 (CVSS bandında Düşük), etiket Yüksek
- V001 ve V008: skor 9.8 (Kritik), etiket Yüksek
- V028: skor 9.1 Yüksek, ama aynı skordaki V023 ve V027 Kritik

Bu çelişki 19/35 kayıtta var. Yani modelin verdiği skor ile verdiği sınıf aynı değerlendirmenin sonucu değil.

### K3: Bağımlılık bulgularını abartma (4 kayıt)

V022, V023, V025 ve V027'ye Kritik verilmiş. Uzman bunları Yüksek'te tutuyor, çünkü Trivy bulgusu paketin uygulamada erişilebilir bir kod yolunda kullanıldığını tek başına kanıtlamıyor. Prompt'taki ölçütte "Yüksek CVSS tek başına Kritik yapmaz" kuralı yazılı olduğu halde model bu kurala uymamış.

Bağımlılık bulgularındaki 9/15 uyum da modelin bu kayıtları doğru ayırt ettiğini göstermiyor: uzman bunların çoğuna Yüksek demiş, model de zaten her şeye Yüksek diyor.

### K4: Uygulamaya özgü kanıtı görememe (2 kayıt)

V001 (SQLi ile admin girişi) ve V008 (admin kaydı) Juice Shop'ta doğrudan sömürülebiliyor ve yönetici yetkisi veriyor; uzman ikisini de Kritik saymış. Model ikisine de Yüksek vermiş. Model, girdide doğrudan sömürü kanıtı (notes alanındaki challenge adı) olan bulgularla yalnızca paket sürümüne dayanan bulguları birbirinden ayıramıyor. K3 ile birlikte düşünüldüğünde, uzman ölçütünün temel ayrımını, yani "kanıt var mı?" sorusunu, kullanmıyor.

### K5: EPSS'i yok sayma (10 kayıt)

EPSS değeri olan 15 kaydın 10'unda (V022, V023, V025–V027, V032–V036) gerekçede EPSS'ten hiç söz edilmiyor. Skor CVSS'e eşit olduğu için EPSS'in skora hiçbir etkisi de yok. Örnek: V024'ün EPSS'i en yüksek (0.21333), V028'inki çok düşük (0.00332). Model V024'e 7.2, V028'e 9.1 vermiş, yani yalnızca CVSS'i izlemiş.

### K6: Alan karışıklığı ve biçim hataları

- **V035:** Skor alanına EPSS değeri (0.00718) yazılmış, etiket Düşük.
- **Yanlış anahtar adı:** Tutarlılık testinde model V035 için etiket alanının adını her seferinde `risk0_label_llm` diye yazdı. v1'in kodu bu anahtarı tanımadığı için yanıtı "eksik" sayıp yeniden denedi.
- **Ollama 500 hatası:** v1'de V014 bu hatayla atlandı. Tutarlılık testinde de V012'nin bir denemesi aynı hatayı verdi.

## 4. Tutarlılık testi

Her kayıt, v1'in prompt'u ve ayarları değiştirilmeden 3 kez çalıştırıldı (`ai/v1_tutarlilik.py`). Zaman kısıtı nedeniyle test, farklı türleri temsil eden 3 kayıtla sınırlı tutuldu:

- **V001:** uygulama bulgusu, uzmana göre Kritik
- **V012:** düşük önemli uygulama bulgusu, uzmana göre Düşük
- **V035:** bağımlılık bulgusu, v1'deki alan hatasının görüldüğü kayıt

| Kayıt | CVSS | v1 kayıtlı skor | Tekrar 1 | Tekrar 2 | Tekrar 3 | Etiketler | Uzman |
|---|---|---|---|---|---|---|---|
| V001 | 9.8 | 9.8 | 9.8 | 9.8 | 9.8 | Yüksek ×3 | Kritik |
| V012 | 4.3 | 4.3 | 4.3 | 4.3 | 4.3 | Yüksek ×3 | Düşük |
| V035 | 9.8 | **0.00718** | 9.8 | 9.8 | geçersiz | Kritik ×2 | Orta |

- **Skor standart sapması:** 0 (üç kayıtta da). Etiket hiçbir kayıtta değişmedi.
- **Geçersiz yanıt:** 9 tekrardan 1'i. V035'in 3. tekrarında model, 3 denemenin hepsinde yanlış anahtar adı (`risk0_label_llm`) yazdı.
- **Süre:** Tekrar başına ortalama 23.9 sn. Log'daki tek denemeler 6–11 sn sürüyor; aradaki fark biçim hatalarından ve 500 hatasından kaynaklanan yeniden denemeler.

**Yorum:**
- Tutarlılığın yüksek çıkması bir başarı değil. Skor CVSS'ten kopyalandığı ve `temperature` 0.1 olduğu için çıktı zaten değişmiyor.
- V001 ve V012'nin yanlış etiketi her tekrarda aynı kalıyor. Yani hatalar rastgele değil, sistematik; tekrar çalıştırmak ya da ortalama almak sonucu düzeltmez.
- V035'in kayıtlı sonucu (0.00718, Düşük) tekrarlanamadı; artık 9.8 ve Kritik çıkıyor. Bölüm 2'deki Spearman üstünlüğü bu tek seferlik hataya dayandığı için geçerli değil. Yeni etiket (Kritik) de uzmandan (Orta) daha uzak.

## 5. Gerekçe kalitesi

Gerekçeler kural tabanlı olarak işaretlendi (`v1_hata_analizi.py`) ve elle okundu.

| Sorun | Kayıt sayısı | Kayıtlar |
|---|---|---|
| Ölçüt metnini kopyalama ("yönetici yetkisi"ni ilgisiz kayıtlarda kullanma) | 14 | V004, V005, V006, V010, V012, V016, V017, V023, V024, V025, V026, V029, V032, V034 |
| Girdiyi olduğu gibi tekrar etme ("Vuln ID: ..., CVE ID: ...") | 11 | V004, V006, V011, V012, V021, V024, V028, V030, V031, V033, V036 |
| Yarım kesilmiş gerekçe | 4 | V027, V028, V031, V036 |
| İngilizce gerekçe | 3 | V008, V027, V036 |
| Uydurma CVE (kayıtta CVE yokken "CVE-2023-XXXX") | 1 | V003 |

Betiğin işaretlemediği 9 gerekçe de (V001, V002, V007, V009, V013, V015, V018, V019, V020) elle okununca sorunlu çıkıyor:

- **Kendisiyle çelişme:** V002 aynı paragrafta hem "yönetici kimlik doğrulama gerekir" hem "gerekmeyecek" diyor.
- **Uydurma değer:** V018'in gerekçesinde, skor 3.1 olduğu halde "kritik seviyesi yaklaşık 8.5" yazıyor.
- **Girdiyle çelişme:** Birçok gerekçede (V001, V002, V005, V019) girdide `AC:L` yazdığı halde "yüksek saldırı karmaşıklığı" deniyor.

Bu yüzden 35 gerekçeden hiçbiri bir analistin kararı destekleyecek biçimde kullanabileceği nitelikte değil. Bu sonuç, v1 gerekçelerinin pano ve grafik hover'larında gösterilmemesi kararının da dayanağıdır.

## 6. Olası nedenler

| Neden | Dayanak |
|---|---|
| Model küçük (3.8B) ve talimat takibi zayıf | Ölçüt kuralları yazılı olduğu halde uygulanmıyor (K3); skor ile etiket çelişiyor (K2) |
| Prompt Türkçe | S1 Ollama denemesinde küçük modellerin Türkçe talimatta formattan saptığı görülmüştü; v1 buna rağmen Türkçe prompt kullanıyor. İngilizce gerekçeler, girdinin tekrarı ve anahtar adı hataları bununla uyumlu |
| Skor ve etiket ayrı ayrı isteniyor | Etiketi skordan kodla türetmek yerine modele ikisini birden sordurmak K2'ye yol açıyor |
| Puanlama ölçeği tanımsız | Prompt 0–10 arası bir skor istiyor ama aralıkların ne anlama geldiğini söylemiyor. Bu yüzden model girdideki tek sayısal ölçeği, yani CVSS'i, kopyalıyor |
| Örnek yok (zero-shot) | Model, "kanıt var / yok" ayrımının nasıl uygulandığını hiç görmüyor (K3, K4) |
| `num_predict` sınırı yok | Yarım kesilmiş ve uzun, kendini tekrar eden gerekçeler |
| Anahtar adlarının sıkı denetimi yok | Yanlış anahtarlar yalnızca yeniden denemeye yol açıyor; geçersiz yanıt sayısı ölçülmüyor |

## 7. v2 için sonuçlar

1. **Modeli değiştir:** `qwen2.5:7b`. Ama iyileşmenin modelden mi prompttan mı geldiğini ayırmak için v1 prompt'u bir kez de qwen2.5:7b ile çalıştırılmalı (kontrol satırı, S4-K4).
2. **Prompt'u İngilizce yaz**, `temperature 0`, `num_predict` ile çıktı sınırı.
3. **Puanlama rubriği ekle:** her skor aralığının ne anlama geldiği, CVSS'in yalnızca bir girdi olduğu, EPSS'in ve kanıtın nasıl tartılacağı.
4. **Kanıt ayrımını açık bir kural olarak yaz:** uygulamada doğrulanmış sömürü (challenge kanıtı) ile yalnızca paket sürümüne dayanan bulgu farklı değerlendirilmeli.
5. **Modelden yalnızca skor iste**, sınıfı kodda skordan türet. Böylece K2 tamamen ortadan kalkar.
6. **Few-shot örnekler kullan**, ama örnekleri değerlendirmeden çıkar.
7. **Anahtar adlarını sıkı denetle**, geçersiz yanıtları say ve raporla.
8. **Başarı ölçütü:** v2, uzman etiketleriyle uyumda en azından CVSS bandını (20/35) geçmeli. Geçemezse model sıralamaya bir şey katmıyor demektir.

## 8. Sınırlılıklar

- Tutarlılık testi 3 kayıtla sınırlı. Sonuç (std 0) skorun CVSS kopyası olmasıyla açıklandığı için kayıt sayısını artırmanın bu sonucu değiştirmesi beklenmiyor.
- Gerekçe sorunlarının bir kısmı kural tabanlı işaretlendi, eksik ya da fazla işaret olabilir. Bölüm 5'teki tablo elle kontrol edildi.
- Uzman etiketleri tek kişinin (K2) değerlendirmesi; etiketleyiciler arası uyum ölçülmedi.
