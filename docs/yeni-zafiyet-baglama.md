# Yeni zafiyetlerin saldırı grafiğine bağlanması

## Sorun

Dondurulmuş envanterdeki 36 kaydın grafikteki yeri (giriş noktası, ön koşul, kazanım, hedef) ekip tarafından belirlendi. Yeni bir taramadan ya da farklı bir seçimden gelen kayıtlarda bu alanlar yoktu. `graph/generate_edges.py` hedefi yalnızca 36 kaydın CWE'lerini kapsayan bir listeden buluyordu. Bu yüzden örnek verideki 254 yeni adayın **175'i (%69)** hiçbir hedefe bağlanamıyordu. Bu kayıtlar hiçbir saldırı yoluna girmiyor, risk hesabında da yer almıyordu.

## Çözüm: üç katman ve kullanıcı onayı

Uygulamanın 3. adımında seçim kaydedilince her yeni kayıt için sırayla:

| Katman | Kaynak | Ne yapar |
|---|---|---|
| 1. Ekip kuralı | `graph/generate_edges.py` (`map_to_target`) | Dondurulmuş envanterle aynı CWE kümeleri. Tutarlılık için ilk sırada. |
| 2. MITRE CWE etkisi | `inventory/cwe_etki.csv` | CWE'nin MITRE kataloğundaki "Common Consequences" alanından en ağır teknik etki → hedef. |
| 3. AI önerisi | Yerel model (Ollama, model v2 ile aynı) | Kapalı listelerden hedef, giriş noktası, ön koşul ve kazanım seçer; gerekçesini yazar. İstek üzerine çalışır. |
| Kullanıcı onayı | 3. adım, "Grafiğe bağlantı" tablosu | Her öneri değiştirilebilir; değiştirilen satır "elle" olarak işaretlenir. |

Seçilen hedef envanterin isteğe bağlı `hedef` sütununa yazılır; kaynağı `hedef_kaynagi`, gerekçesi `hedef_gerekcesi` sütunlarına. `generate_edges.py` bu sütun doluysa onu kullanır. Dondurulmuş envanterde bu sütun yoktur, ekibin grafiği (`graph/edges.json`) birebir aynı kalır.

Hiçbir katmanın bağlayamadığı kayıt sessizce kopuk kalmaz:
- 3. adımda "Hedefi belirsiz" sayısı görünür.
- 4. adımda bu kayıtlar uyarıyla listelenir.

## MITRE CWE etki tablosu

`tools/cwe_etki_tablosu.py`, MITRE CWE v4.14 kataloğundan (`cwec_v4.14.xml`, PyPI'daki `cwe2` paketiyle gelir) `inventory/cwe_etki.csv`'yi üretir: 1372 CWE, 722'sine hedef bulundu.

Etki → hedef kuralı. Sıra önemli, ilk tutan kazanır, en ağır sonuç önce gelir:

| MITRE teknik etkisi | Hedef |
|---|---|
| Execute Unauthorized Code or Commands | Kod çalıştırma |
| Gain Privileges or Assume Identity | Yönetici erişimi |
| Read Application Data / Read Memory / Read Files or Directories | Veri sızıntısı |
| DoS: ... | Hizmet kesintisi |

- **Üst CWE'ye bakma:** Bir CWE'nin kendi etkileri belirleyici değilse ("Bypass Protection Mechanism", "Varies by Context" gibi), üst CWE'lerine (ChildOf, en fazla 3 seviye) bakılır.
- **Olası diğer hedefler:** Tablo bunları da tutar. 3. adımdaki gerekçede gösterilir.
- **Bilinen sınır:** MITRE bir CWE için olası bütün sonuçları listeler; kural en ağırını seçer, yani en kötü durumu varsayar. Örneğin XSS (CWE-79) MITRE'ye göre "kod çalıştırma"ya düşer, ekip kuralı ise "hesap ele geçirme" der. Bu yüzden ekip kuralı önce gelir, MITRE yalnızca ekip kuralının bilmediği CWE'lerde kullanılır.

## AI önerisi

- **Model:** Model v2 ile aynı (`qwen2.5:7b`, temperature 0, sabit seed, JSON çıktı). Ayrıntı: `app/pipeline/baglanti.py`.
- **Modele verilen bilgi:**
  - kaydın kanıtı (model v2'nin `bulgu_metni`)
  - MITRE etkileri
  - kural önerisi
  - 5 hedefin, 5 giriş noktasının ve yetkinlik sözlüğünün tanımları
  - dondurulmuş envanterden 3 örnek (V001, V025, V027)
- **Doğrulama:** Yanıt sıkı denetlenir. Hedef, giriş ve yetkinlikler yalnızca kapalı listelerden olabilir; geçersiz yanıtta en fazla 3 kez yeniden sorulur.
- **Trivy kayıtları:** Giriş noktası kural gereği her zaman `dependency` kalır.
- **Kullanıcı kararları korunur:** Seçim yeniden kaydedilince AI ve elle verilmiş kararlar korunur.

## Ölçüm (örnek veri, `inventory/raw/`)

| Seçim | Yeni kayıt | Önce hedefe bağlı | Kural katmanlarından sonra | AI'ya ya da elle kalan |
|---|---|---|---|---|
| Kurala göre seçim | 46 | 21 (%46) | 42 (%91) | 4 |
| Bütün adaylar | 254 | 79 (%31) | 196 (%77) | 58 |

Kalan 58 kaydın 17'si CWE'siz. Diğerlerinin çoğu teknik etkisi tanımlı olmayan kategori ya da genel CWE'ler: CWE-1104 eski bileşen, CWE-284 erişim denetimi, CWE-16 yapılandırma. Bunlar AI önerisine ya da kullanıcıya kalır.

## Bilinen sınırlar

- **Ön koşul ve kazanım alanları:** Bunları yalnızca AI önerisi ya da kullanıcı doldurur, kural katmanları doldurmaz. Yeni kayıtlar kural katmanlarıyla bir hedefe bağlanır ama zincire girmez.
- **Varsayılan alanlar:** Yeni kayıtların varlık kritikliği gibi bazı alanları varsayılandır (3). Bu kayıtların grafikteki yeri dondurulmuş envanterdekiler kadar güvenilir değildir; 4. adımda bu belirtilir.
- **AI önerisinin değerlendirilmesi:** AI önerisi uzman etiketleriyle değerlendirilmedi. Risk skorundaki gibi bir uyum ölçümü (24/33) burada yok.
