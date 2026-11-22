# Demo senaryosu (uygulama, 3–4 dakika)

**Amaç:** Hocalara projenin bütün hattını tek ekranda göstermek: hedef → tarama → bulgu seçimi → saldırı grafiği ve AI önceliklendirmesi → savunmaların bu zafiyetleri yakalaması.

**Ana mesaj:** "Zafiyetleri bulmak yetmez; hangisinin gerçekten tehlikeli olduğunu saldırı yollarıyla ve bağlamla sıralıyoruz, sonra kontrollerin bunlardan neyi durdurduğunu kanıtlıyoruz."

## Demodan önce (yarım saat önce)

- [ ] Lab ve pano açık: `cd defense` → `docker compose --profile siem up -d` → `docker compose ps` (hepsi `running`)
- [ ] `streamlit run app/main.py`, tarayıcıda uygulama açık
- [ ] **Canlı tarama demoda yapılmaz:** ZAP birkaç dakika sürer. Demodan önce bir canlı çalıştırma tamamlanmış olsun (2–4. adımlar dahil); demoda "Önceki çalıştırmayı aç" ile açılır
- [ ] Grafana ayrı sekmede açık ve giriş yapılmış, zaman aralığı "Son 15 dakika"
- [ ] (İsteğe bağlı) Ollama açık; yalnızca yeni kayıt skorlanacaksa gerekir
- [ ] Ekran çözünürlüğü 1920×1080, tarayıcı yakınlaştırma %90; bildirimler kapalı
- [ ] Yedek ekran kaydı masaüstünde, oynatıcıda açık

## Akış

| Süre | Adım | Ekranda | Söylenecek |
|---|---|---|---|
| 0:00–0:20 | 1. Hedef | Hedef kartı, yeşil Docker/konteyner durumu | "Uygulama yalnızca kendi izole lab'ımızdaki hedefleri tarayabiliyor; adres girme alanı yok. Juice Shop WAF arkasında, segmentli bir ağda çalışıyor." |
| 0:20–0:45 | 2. Tarama | Önceki çalıştırmayı aç → ham veri tablosu | "Üç kaynak: ZAP pasif web taraması, Trivy imaj taraması, Juice Shop'un challenge listesi. Canlı tarama birkaç dakika sürdüğü için önceden çalıştırdık." |
| 0:45–1:20 | 3. Bulgular | Aday bulgu listesi, referans farkı, seçim | "Ham çıktılardan aday bulguları çıkarıyoruz ve ekibin elle doğruladığı envanterle karşılaştırıyoruz. Yeni bir bulgu varsa burada görünür; hangisinin grafiğe gireceğine kullanıcı karar veriyor." |
| 1:20–2:20 | 4. Grafik | Özet metrikleri → grafik → en riskli yollar paneli → bir düğümün hover'ı | "36 zafiyet, 72 kenar, 36 saldırı yolu. Yeşil elmaslar giriş noktaları, yıldızlar hedefler. Kırmızı yollar en riskli 5 yol. Bir zincir var: arama kutusundaki SQL enjeksiyonu parola karmalarını veriyor, zayıf PBKDF2 bunları yönetici parolasına çeviriyor (V002 → V025 → admin)." |
| 2:20–2:50 | 4. Grafik, AI tablosu | CVSS ve AI sırası yan yana | "CVSS'e göre libc6 açığı V035 9.8 ile en üstte. Model 7.3 veriyor: bu yalnızca bir paket sürümü eşleşmesi, uygulamada erişilebilirliği doğrulanmamış. Buna karşılık V001'i (giriş formunda SQLi, doğrudan yönetici erişimi) Kritik tutuyor. Modelin uzman etiketleriyle uyumu 24/33, yalnızca CVSS 19/33." |
| 2:50–3:30 | 5. Savunma testi | "Saldırı testlerini çalıştır" → sonuç tablosu | "Şimdi grafikteki zafiyetlere kendi lab'ımızda saldırı deniyoruz. Her saldırının yanında aynı adrese zararsız bir istek var: WAF ve sanal yamalar saldırıyı engelliyor, normal kullanımı engellemiyor. Güvenlik başlıkları, hata sayfası ve hız sınırı da kontrol ediliyor: 41 kontrol, 14 engelleme, beklenmeyen sonuç yok." |
| 3:30–3:50 | Grafana | "Sonuçları savunma panosunda gör" | "Aynı saldırılar merkezi panoda: WAF engellemeleri ATT&CK tekniklerine göre, IDS alarmları ağın hangi bacağında görüldüğüyle birlikte." |
| 3:50–4:40 | 6. Önlem seçimi | Bütçe kaydırıcısı 16 saat → metrikler → kritik varlık tablosu; "Önlemler test edilmiş say" anahtarı | "Kontroller açıkken bile yollar kalıyor; çoğu kütüphane açığı, yama gerektiriyor. Soru şu: sınırlı eforla riski en çok hangi önlemler azaltır? 15 aday önlemi bütçeye göre deniyoruz; bütün bileşimler deneniyor, yani sonuç en iyisi. 16 saatte yol riski %33 düşüyor; önlemler uygulanıp test edilirse 10 yol daha kesiliyor. Kesinti istemeyenleri de ayrıca seçebiliyoruz." |
| 4:40–4:50 | Kapanış | 4. adım, "Hepsini indir" | "Her çalıştırmanın envanteri, skorları, grafiği ve test sonuçları tek dosyada dışa aktarılabiliyor." |

## Bir şey bozulursa (B planları)

| Sorun | Geçilecek yol | Söylenecek |
|---|---|---|
| Docker / lab açılmıyor | 1. adımda "Örnek veriyle başlat"; 3. adımda dondurulmuş envanteri uygula; 4. adım aynı | "Ekibin daha önce topladığı tarama dosyalarıyla devam ediyorum; akış aynı kod." |
| Grafik oluşmuyor | Önceki çalıştırmayı aç (grafik hazır) | — |
| Savunma testi düğmesi pasif ya da hata | `inventory/raw/after_controls/test-waf.log` dosyasını göster (S5-K2) | "Aynı testin kayıtlı çıktısı; kontroller açıkken 41 kontrol, 0 beklenmeyen sonuç." |
| Grafana açılmıyor | Demodan önce alınmış pano ekran görüntüleri | "Panonun aynı testten sonraki hali." |
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
- **İçerik:** Yukarıdaki akışın tamamı, 4 dakikayı geçmeyecek biçimde. Sesli anlatım isteğe bağlı; konuşmasız kayıtta canlı anlatılır.
- **Kayıt öncesi:** Bildirimleri kapat, masaüstündeki kişisel dosyaları gizle, tarayıcıda yalnızca uygulama ve Grafana sekmeleri açık olsun.
- **Kayıttan sonra:** Dosyayı `docs/` dışında bir yere koy (repoya büyük video eklenmesin); demo bilgisayarında ve bir USB bellekte yedek tut.
