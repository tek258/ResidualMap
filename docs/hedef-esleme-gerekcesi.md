# Hedef Eşleme Gerekçesi (`docs/hedef-esleme-gerekcesi.md`)

## 1. Saldırı Grafındaki 5 Hedefin Tanımı

Saldırı grafiğinde zafiyet düğümlerinin (`V001`–`V036`) ulaşabileceği 5 ana hedef düğümü tanımlanmıştır[cite: 1]:

1. **`node_target_admin` — Yetkisiz Admin Erişimi:** Uygulama veya sistem üzerinde yönetici/admin ayrıcalıklarının elde edilmesi, yetkisiz yönetici hesabı oluşturulması ya da kimlik bilgilerinin ele geçirilmesi yoluyla yönetim düzeyinde kontrol sağlanmasıdır[cite: 1].
2. **`node_target_account_takeover` — Hesap Ele Geçirme:** Kullanıcı oturumlarının, kimlik doğrulama/yetkilendirme mekanizmalarının veya hesap verilerinin suistimal edilmesiyle kurban hesabın kontrolünün ele geçirilmesidir[cite: 1].
3. **`node_target_leak` — Hassas Veri Sızıntısı:** Gizli dokümanların, veritabanı şemalarının, dosya sistemindeki kritik verilerin veya hata/sürüm sızıntılarıyla hassas bilgilerin yetkisiz kişilere açığa çıkmasıdır[cite: 1].
4. **`node_target_rce` — RCE ve Sistem Ele Geçirme:** Sunucu veya çalışma zamanı üzerinde uzaktan kod çalıştırma (Remote Code Execution) veya tehlikeli fonksiyon/komut enjeksiyonu yoluyla ana sistem kontrolünün elde edilmesidir[cite: 1].
5. **`node_target_dos` — Hizmet Engelleme (DoS):** Kaynak tüketimi, hatalı girdi işleme veya özel zafiyet tetiklemeleriyle servisin yavaşlatılması ya da erişilemez hale getirilmesidir[cite: 1].

---

## 2. CWE → Hedef Eşleme Kuralları

Zafiyetlerin CWE sınıflandırmaları ile hedef düğümleri arasındaki temel kural eşleşmeleri şu şekilde kurgulanır[cite: 1]:

* **`node_target_admin`:** Yetki yükseltme, kimlik bilgisi ifşası, SQL/kimlik doğrulama zafiyetleri ve yönetici yetkisi doğuran CWE sınıfları[cite: 1].
* **`node_target_account_takeover`:** XSS, CSRF, IDOR/erişim kontrolü zafiyetleri, zayıf parola/şifre sıfırlama ve açık yönlendirme gibi hesap/oturum ele geçirme odaklı CWE sınıfları[cite: 1].
* **`node_target_leak`:** Dizin listeleme, XXE/dosya okuma, path traversal, zayıf kriptografi ve ayrıntılı hata/bilgi ifşası içeren CWE sınıfları[cite: 1].
* **`node_target_rce`:** Komut/şablon enjeksiyonu, tehlikeli kod/fonksiyon çalıştırma ve bellek/sistem seviyesinde kod yürütmeye yol açan CWE sınıfları[cite: 1].
* **`node_target_dos`:** ReDoS, kaynak/bellek tüketimi ve hizmet sürekliliğini bozan CWE sınıfları[cite: 1].

*(Not: Mevcut `edges.json` kaydında CWE alanı ayrıca tutulmamakta, hedef bağlantıları `vuln_to_target` kenarlarında `basis: "rule"` dayanağıyla tanımlanmaktadır[cite: 1].)*

---

## 3. Ek CWE Listesi

Temel kural setine ek olarak genişletilmiş/tamamlayıcı CWE kapsamı:

* **Ek CWE'ler:** `[CWE-XXX, CWE-YYY, ... — genişletilmiş kural setindeki ek CWE kodlarını buraya listeleyin]`
* **Uygulama Kuralı:** Ek CWE listesinde yer alan kayıtlar, ilgili hedef düğümüne kural tabanlı (`basis: "rule"`) olarak bağlanır; doğrudan CWE eşleşmesi bulunmayan durumlarda bir sonraki aşamadaki CVSS tahmin kuralı devreye girer.

---

## 4. CVSS'ten Tahmin Kuralı (`basis: "cvss"`)

Doğrudan kural veya CWE eşleşmesi üretilemeyen ya da tahmini bağlantı kurgusu gereken zafiyetlerde CVSS puanı baz alınarak hedef/bağlantı tahmini yapılır:

* **Tetiklenme Koşulu:** Doğrudan kural eşleşmesi sağlanamadığında ve zafiyetin geçerli bir `cvss_score` değeri bulunduğunda uygulanır.
* **Skor / Hedef Tahmin Mantığı:** `[Örn: CVSS >= 9.0 ise node_target_rce / node_target_admin, 7.0–8.9 arası ise node_target_account_takeover / node_target_leak, < 7.0 ise node_target_dos — kendi kural eşiklerinizi buraya yazın]`
* **Görselleştirme Karşılığı:** `basis` değeri `"cvss"` olan kenarlar graf üzerinde **kesikli (`dashes=True`) tahmini bağlantı** olarak gösterilir.

---

## 5. Kenar Sayıları ve Dayanak (`basis`) Dağılımı

Mevcut `edges.json` dosyasında toplam **72 kenar** bulunmaktadır[cite: 1]:

* **Dayanak (`basis`) bazında dağılım:**
  * `rule`: **72 kenar** (%100)[cite: 1]
  * `cvss`: **0 kenar** (%0)[cite: 1]
* **İlişki (`relation`) bazında dağılım:**
  * `entry_to_vuln`: **36 kenar** (tamamı `basis: "rule"`)[cite: 1]
  * `vuln_to_target`: **36 kenar** (tamamı `basis: "rule"`)[cite: 1]
* **Hedef düğümlere (`vuln_to_target`) giden 36 kenarın dağılımı (tamamı `basis: "rule"`):**
  * `node_target_account_takeover`: **11 kenar**[cite: 1]
  * `node_target_leak`: **9 kenar**[cite: 1]
  * `node_target_admin`: **8 kenar**[cite: 1]
  * `node_target_rce`: **5 kenar**[cite: 1]
  * `node_target_dos`: **3 kenar**[cite: 1]