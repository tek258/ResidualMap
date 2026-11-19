# Hedef Eşleme Gerekçesi

## 1. Saldırı Grafındaki 5 Hedefin Tanımı

Saldırı grafiğinde zafiyet düğümlerinin (`V001`–`V036`) ulaşabileceği 5 ana hedef düğümü tanımlanmıştır:

1. **`node_target_admin` — Yetkisiz Admin Erişimi:** Uygulama veya sistem üzerinde yönetici/admin ayrıcalıklarının elde edilmesi, yetkisiz yönetici hesabı oluşturulması ya da kimlik bilgilerinin ele geçirilmesi yoluyla yönetim düzeyinde kontrol sağlanmasıdır.
2. **`node_target_account_takeover` — Hesap Ele Geçirme:** Kullanıcı oturumlarının, kimlik doğrulama/yetkilendirme mekanizmalarının veya hesap verilerinin suistimal edilmesiyle kurban hesabın kontrolünün ele geçirilmesidir.
3. **`node_target_leak` — Hassas Veri Sızıntısı:** Gizli dokümanların, veritabanı şemalarının, dosya sistemindeki kritik verilerin veya hata/sürüm sızıntılarıyla hassas bilgilerin yetkisiz kişilere açığa çıkmasıdır.
4. **`node_target_rce` — RCE ve Sistem Ele Geçirme:** Sunucu veya çalışma zamanı üzerinde uzaktan kod çalıştırma (Remote Code Execution) veya tehlikeli fonksiyon/komut enjeksiyonu yoluyla ana sistem kontrolünün elde edilmesidir.
5. **`node_target_dos` — Hizmet Engelleme (DoS):** Kaynak tüketimi, hatalı girdi işleme veya özel zafiyet tetiklemeleriyle servisin yavaşlatılması ya da erişilemez hale getirilmesidir.

---

## 2. CWE → Hedef Eşleme Tablosu (`generate_edges.py` Kümeleri)

`GRANTS_TARGETS` eşleşmesi olmadığında zafiyetin `cwe_id` değerine göre uygulanan kümeler ve tek cümlelik gerekçeleri:

| Hedef Düğümü | CWE Kümesi / Kuralı | Tek Cümlelik Gerekçe |
| :--- | :--- | :--- |
| `node_target_admin` | `ADMIN_CWES` (`cwe-798`, `cwe-521`, `cwe-20`, `cwe-290`, `cwe-285`, `cwe-915`) ve adı `login`/`admin` içeren `cwe-89` | Doğrudan yönetici yetkisi, kimlik doğrulama/yetkilendirme aşımı veya ayrıcalık yükseltme imkânı verir. |
| `node_target_account_takeover` | `ACCOUNT_CWES` (`cwe-79`, `cwe-639`, `cwe-640`, `cwe-352`, `cwe-601`, `cwe-693`, `cwe-749`, `cwe-331`) | İstemci taraflı saldırılar veya oturum/erişim kontrol zafiyetleriyle kullanıcı hesabının ele geçirilmesini sağlar. |
| `node_target_leak` | `LEAK_CWES` (`cwe-200`, `cwe-548`, `cwe-611`, `cwe-209`, `cwe-264`, `cwe-497`, `cwe-328`) ve `login`/`admin` içermeyen `cwe-89` | Hassas uygulama verilerinin, hata/yapılandırma detaylarının veya korumalı kayıtların sızmasına yol açar. |
| `node_target_rce` | `RCE_CWES` (`cwe-1321`, `cwe-94`, `cwe-22`, `cwe-176`, `cwe-122`, `cwe-119`) | Kod/nesne enjeksiyonu, dizin geçişi veya bellek bozulması üzerinden kod yürütme zemini oluşturur. |
| `node_target_dos` | `DOS_CWES` (`cwe-400`, `cwe-476`, `cwe-248`) | Kaynak tükenmesi veya yakalanmayan hata/boş gösterge durumlarıyla servisin durmasına neden olur. |

---

## 3. Yetkinliğe Göre Hedef Seçimi (`GRANTS_TARGETS`)

Hedef belirlenirken `map_to_target` içinde **ilk olarak `GRANTS_TARGETS`** kontrol edilir, ancak eşleşme yoksa CWE kümelerine geçilir:

* `admin_session` → `node_target_admin`
* `admin_credentials` → `node_target_admin`
* `forged_identity` → `node_target_admin`
* `stolen_session` → `node_target_account_takeover`

CWE kümeleri yerine önce `GRANTS_TARGETS` bakılmasının nedeni, zafiyetin kazandıracağı yeteneğin saldırının pratik sonucunu doğrudan belirlemesidir. Örneğin **V025** (`CWE-328`) normalde `LEAK_CWES` içinde olduğu için `node_target_leak` hedefine giderdi, ancak `admin_credentials` kazandırdığı için `node_target_admin` hedefine eşlenir.

---

## 4. Zincirleme (`Chains To`) ve Giriş Kuralı

* Ön koşulu (`requires_capability != "none"`) bulunan zafiyetlere doğrudan giriş (`Entry Point`) kenarı verilmez; bu zafiyetlere yalnızca gerekli yeteneği (`grants_capability`) sağlayan önceki zafiyet üzerinden `Chains To` kenarıyla erişilir.
* Mevcut envanterdeki tek zincir **V002 → V025** (`password_hashes`) bağlantısıdır.

---

## 5. Yedek Kural ve Üretim Sayıları

* **Yedek kural:** `GRANTS_TARGETS`, özel `cwe-89` kuralı ve CWE kümeleri eşleşmezse zafiyet adında `"admin"` geçmesi durumunda `node_target_admin` seçilir; aksi halde `None` döner. Mevcut envanterde hiçbir kayıt bu yedek kurala düşmez (`"Tüm zafiyetler bir hedefe eşlendi"`).
* **`python graph/generate_edges.py` çıktısı:**
  * **Toplam 72 kenar:** `Entry Point` 35, `Leads To` 36, `Chains To` 1
  * **Girişler:** `dependency` 14, `web` 13, `api` 4, `login` 2, `search` 2
  * **Hedefler:** `account_takeover` 12, `admin` 8, `rce` 7, `leak` 6, `dos` 3