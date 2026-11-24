# Demo senaryosu (uygulama, ~6 dakika)

**Amaç:** Hocalara projenin bütün hattını tek ekranda göstermek: hedef → tarama → bulgu seçimi → saldırı grafiği ve AI önceliklendirmesi → savunmaların bu zafiyetleri yakalaması.

**Ana mesaj:** "Zafiyetleri bulmak yetmez; hangisinin gerçekten tehlikeli olduğunu saldırı yollarıyla ve bağlamla sıralıyoruz, sonra kontrollerin bunlardan neyi durdurduğunu kanıtlıyoruz."

## Demodan önce (yarım saat önce)

- [ ] `streamlit run app/main.py`, tarayıcıda uygulama açık
- [ ] **Yan menü → "Ortamı başlat" → "Hepsini başlat":** Docker Desktop, lab, savunma panosu ve Ollama sırayla açılır, model belleğe yüklenir. Dört satır da yeşil olmalı (elle: `cd defense` → `docker compose --profile siem up -d`)
- [ ] **Canlı tarama demoda yapılmaz:** ZAP birkaç dakika sürer. Demodan önce bir canlı çalıştırma tamamlanmış olsun (2–4. adımlar dahil); demoda "Önceki çalıştırmayı aç" ile açılır
- [ ] Grafana ayrı sekmede açık ve giriş yapılmış, zaman aralığı "Son 15 dakika"
- [ ] **Ollama açık ve model ısınmış:** "Ortamı başlat" bunu yapar (elle: `ollama run qwen2.5:7b "merhaba"`; ilk çağrı 10-20 sn sürer). 3. adımdaki AI bağlantı önerisi, 4. adımdaki canlı skorlama ve 6. adımdaki plan açıklaması bunu gerektirir. Demodan önce her birini bir kez dene
- [ ] Ekran çözünürlüğü 1920×1080, tarayıcı yakınlaştırma %90; bildirimler kapalı
- [ ] Yedek ekran kaydı masaüstünde, oynatıcıda açık

## Akış

| Süre | Adım | Ekranda | Söylenecek |
|---|---|---|---|
| 0:00–0:30 | Özet | Açılış sayfası: 5 kart, **"Yapay zekâ nerede?"** şeridi ve "Kontroller sonrası" grafik | "Sonuçtan başlayalım: 36 zafiyet, 36 saldırı yolu. Kontroller açıkken artık risk %32 düştü, 13 yol kesildi. 16 saatlik bir önlem planı yol riskini %33 daha azaltıyor. Yerel bir dil modeli üç adımda karar veriyor: bağlantı önerisi, risk skoru ve plan açıklaması. Şimdi bunu nasıl bulduğumuzu gösterelim." → "Demoyu başlat" |
| 0:30–0:50 | 1. Hedef | Hedef kartı, yeşil Docker/konteyner durumu | "Uygulama yalnızca kendi izole lab'ımızdaki hedefleri tarayabiliyor; adres girme alanı yok. Juice Shop WAF arkasında, segmentli bir ağda çalışıyor." |
| 0:50–1:10 | 2. Tarama | Önceki çalıştırmayı aç → ham veri tablosu | "Üç kaynak: ZAP pasif web taraması, Trivy imaj taraması, Juice Shop'un challenge listesi. Canlı tarama birkaç dakika sürdüğü için önceden çalıştırdık." |
| 1:10–2:10 | 3. Bulgular | "Kurala göre seç" → "Seçimi kaydet" → **Grafiğe bağlantı** tablosu → "AI ile öner: belirsizler" → sonra "Dondurulmuş envanteri uygula" → "Seçimi kaydet" | "Yeni bir taramada envanterde olmayan bulgular çıkıyor. Bunların grafikte nereye bağlanacağını üç katmanla buluyoruz: önce ekibin CWE kuralı, sonra MITRE CWE kataloğundaki teknik etki, ikisi de yetmezse yerel model. 46 yeni kaydın 21'i ekip kuralından, 21'i MITRE'den bağlandı, 4'ü belirsiz kaldı; bunları modele soruyoruz. Model kapalı listeden hedef, giriş ve yetkinlik seçip gerekçesini yazıyor; son karar kullanıcıda. Rapordaki sayılarla devam etmek için şimdi dondurulmuş envantere dönüyorum." |
| 2:10–3:00 | 4. Grafik | Özet metrikleri → grafik → en riskli yollar paneli → bir düğümün hover'ı | "36 zafiyet, 72 kenar, 36 saldırı yolu. Yeşil elmaslar giriş noktaları, yıldızlar hedefler. Kırmızı yollar en riskli 5 yol. Bir zincir var: arama kutusundaki SQL enjeksiyonu parola karmalarını veriyor, zayıf PBKDF2 bunları yönetici parolasına çeviriyor (V002 → V025 → admin)." |
| 3:00–4:00 | 4. Grafik, AI | CVSS ve AI sırası yan yana → **Model ne düşündü?** (varsayılan: modelin CVSS'ten en çok ayrıldığı kayıt) → "Bu kaydı şimdi canlı skorla" → "Modele gönderilen tam prompt" | "Risk skorunu yerel bir dil modeli veriyor. Burada modelin ne gördüğü, ne karar verdiği ve neden verdiği görünüyor: kanıtın türü, kimlik doğrulama ihtiyacı, etki. Şimdi bu kaydı canlı skorluyorum, model şu an çalışıyor. CVSS'e göre libc6 açığı V035 9.8 ile en üstte; model 7.3 veriyor çünkü bu yalnızca bir paket sürümü eşleşmesi. Uzman etiketleriyle uyumu 24/33, yalnızca CVSS 19/33." |
| 4:00–4:30 | 5. Savunma testi | "Saldırı testlerini çalıştır" → sonuç tablosu | "Şimdi grafikteki zafiyetlere kendi lab'ımızda saldırı deniyoruz. Her saldırının yanında aynı adrese zararsız bir istek var: WAF ve sanal yamalar saldırıyı engelliyor, normal kullanımı engellemiyor. Güvenlik başlıkları, hata sayfası ve hız sınırı da kontrol ediliyor: 41 kontrol, 14 engelleme, beklenmeyen sonuç yok." |
| 4:30–4:40 | Grafana | "Sonuçları savunma panosunda gör" | "Aynı saldırılar merkezi panoda: WAF engellemeleri ATT&CK tekniklerine göre, IDS alarmları ağın hangi bacağında görüldüğüyle birlikte." |
| 4:40–6:00 | 6. Önlem seçimi | Bütçe kaydırıcısı 16 saat → metrikler → kritik varlık tablosu; "Önlemler test edilmiş say" anahtarı | "Kontroller açıkken bile yollar kalıyor; çoğu kütüphane açığı, yama gerektiriyor. Soru şu: sınırlı eforla riski en çok hangi önlemler azaltır? 15 aday önlemi bütçeye göre deniyoruz; bütün bileşimler deneniyor, yani sonuç en iyisi. 16 saatte yol riski %33 düşüyor; önlemler uygulanıp test edilirse 10 yol daha kesiliyor. Kesinti istemeyenleri de ayrıca seçebiliyoruz. Son olarak planı modele açıklatıyorum: model hesap yapmıyor, sayılar motordan geliyor; model yalnızca yöneticiye anlatıyor ve yazdığı her sayı hesaplananlarla karşılaştırılıyor." → **"Planı AI ile açıkla"** (~15-30 sn) |
| 6:00–6:10 | Kapanış | Yan menü → **"AI izi"**, sonra 4. adım "Hepsini indir" | "Bu çalıştırmada modele yapılan her çağrı burada: ne soruldu, ne cevap verdi, kaç saniye sürdü. Her çalıştırmanın envanteri, skorları, grafiği ve test sonuçları da tek dosyada dışa aktarılabiliyor." |

## Bir şey bozulursa (B planları)

| Sorun | Geçilecek yol | Söylenecek |
|---|---|---|
| Docker / lab açılmıyor | 1. adımda "Örnek veriyle başlat"; 3. adımda dondurulmuş envanteri uygula; 4. adım aynı | "Ekibin daha önce topladığı tarama dosyalarıyla devam ediyorum; akış aynı kod." |
| Grafik oluşmuyor | Önceki çalıştırmayı aç (grafik hazır) | — |
| Savunma testi düğmesi pasif ya da hata | `inventory/raw/after_controls/test-waf.log` dosyasını göster (S5-K2) | "Aynı testin kayıtlı çıktısı; kontroller açıkken 41 kontrol, 0 beklenmeyen sonuç." |
| Grafana açılmıyor | Demodan önce alınmış pano ekran görüntüleri | "Panonun aynı testten sonraki hali." |
| Ollama kapalı / model yanıt vermiyor | AI düğmeleri pasif görünür; "Model ne düşündü?" paneli hazır skorlarla yine çalışır | "Model bu bilgisayarda kapalı; hazır skorların gerekçesini gösteriyorum, canlı çalıştırmayı kayıtta görebilirsiniz." |
| 6. adım açılmıyor | `docs/onlem-secimi.md` ve `report/img/onlem-butce.png` | "Aynı hesabın betikten üretilmiş hali." |
| Hiçbiri çalışmıyor | Yedek ekran kaydı | "Canlı ortamda sorun çıktı, aynı akışın kaydını gösteriyorum." |

## Olası sorular ve kısa cevaplar

- **"Bu taramalar gerçek bir siteye yapılabilir mi?"** Hayır. Hedefler kodda sabit bir izin listesinde ve yalnızca yerel adresler kabul ediliyor; liste dışı bir adres eklenirse uygulama açılmıyor.
- **"ZAP saldırı mı yapıyor?"** Hayır, baseline pasif bir tarama. Saldırı istekleri yalnızca 5. adımdaki sabit test betiğinde ve yalnızca lab hedefine gidiyor.
- **"AI skoru neden güvenilir?"** Uzman etiketleriyle karşılaştırıldı: sınıf uyumu 24/33, yalnızca CVSS 19/33. Ayrıca CVSS gizlenince de baseline'ı geçiyor (22/33). Sınırlılığı: bant içinde ayırt edicilik zayıf, rubrik uzman ölçütünden türetildi (`docs/model-v2-degerlendirme.md`).
- **"Önlemlerin etkisi uygulamadan nasıl biliniyor?"** Metodolojideki etkinlik tablosundan, temkinli (gerekçe) dayanakla: `engeller` 0.63. Uygulanıp test edilince 0.9 olur. Aynı motor, uygulanmış kontrolleri sıfırdan eklediğinde raporun sonuçlarını (163.33) birebir üretiyor; doğrulaması bu.
- **"Efor değerleri nereden?"** Ekip tahmini; her önlemin gerekçesi `inventory/onlem_katalogu.csv`'de. Kesinti gerektirenler (oturumların düşmesi, imaj değişimi) ayrıca işaretli.
- **"Yeni bir zafiyet çıkarsa?"** 3. adımda yeni bulgu olarak görünür, varsayılan alanlarla grafiğe eklenir (uyarıyla). Ollama açıksa 4. adımda modelle skorlanır.

## Yedek ekran kaydı

- **Araç:** Windows'ta Xbox Game Bar (`Win + Alt + R` kaydı başlatır/durdurur) ya da OBS Studio. Çıktı 1080p, MP4.
- **İçerik:** Yukarıdaki akışın tamamı, ~6 dakika. Sesli anlatım isteğe bağlı; konuşmasız kayıtta canlı anlatılır.
- **Kayıt öncesi:** Bildirimleri kapat, masaüstündeki kişisel dosyaları gizle, tarayıcıda yalnızca uygulama ve Grafana sekmeleri açık olsun.
- **Kayıttan sonra:** Dosyayı `docs/` dışında bir yere koy (repoya büyük video eklenmesin); demo bilgisayarında ve bir USB bellekte yedek tut.
