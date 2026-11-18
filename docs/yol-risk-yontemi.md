# Saldırı Yolu Risk Değerlendirme ve Nicelleştirme Yöntemi

Bu doküman, **ResidualMap** saldırı grafiği analizi kapsamında tespit edilen her bir saldırı yolunun (attack path) tek bir sayısal risk değeriyle ifade edilmesi için kullanılan metodolojiyi, yöntem karşılaştırmalarını ve örnek hesaplamaları içermektedir.

---

## 1. Yöntem Karşılaştırması

Saldırı yollarını skorlamak amacıyla iki temel yaklaşım incelenmiştir:

### Yöntem A: Yoldaki En Yüksek CVSS Skoru (Max CVSS)
* **Açıklama:** Yol üzerindeki adımlardan (zafiyetlerden) CVSS taban puanı en yüksek olan değer, doğrudan o yolun risk skoru olarak kabul edilir.
* **Formül:** $\text{Risk} = \max(\text{CVSS}_{v_1}, \text{CVSS}_{v_2}, \dots, \text{CVSS}_{v_n})$
* **Avantajları:** 
  * Hesaplanması çok basittir.
  * Sistemdeki en kritik tekil zafiyeti anında öne çıkarır.
* **Dezavantajları:** 
  * Saldırı zincirinin uzunluğunu veya adımların gerçekleşme olasılığını (zorluğunu) hesaba katmaz. 
  * Çok uzun, karmaşık ve sömürülmesi düşük ihtimalli bir yolla, çok kısa ve kolay bir yolu aynı riske sahip gösterebilir.

### Yöntem B: Sömürülme Olasılıklarının Çarpımı $\times$ Hedef Kritikliği ($Probability \times Criticality$)
* **Açıklama:** Bir saldırı yolunun başarıyla tamamlanabilmesi, zincir üzerindeki tüm adımların sırasıyla ve başarıyla sömürülmesine bağlıdır (bağımlı olaylar zinciri). Bu yöntem, her adımın sömürülme olasılığının ($P_i$, örn. EPSS veya kestirimsel olasılık) kümülatif çarpımını, hedefin iş/varlık kritiklik skoru ($C_{\text{target}}$) ile çarpar.
* **Formül:** $\text{Risk} = \left(\prod_{i=1}^{n} P_i\right) \times C_{\text{target}}$
* **Avantajları:** 
  * Zincir mantığına uygundur; adım sayısı arttıkça başarı olasılığının istatistiksel olarak düşmesini gerçekçi bir şekilde modeller.
  * Hedefin kritiklik derecesini hesaba katarak iş etkisi (business impact) odaklı kararlar alınmasını sağlar.
* **Dezavantajları:** 
  * Doğru olasılık verilerine (örn. EPSS skorları) erişim gerektirir.

---

## 2. Yöntem Seçimi ve Gerekçesi

Karşılaştırma sonucunda **Yöntem B (Sömürülme Olasılıklarının Çarpımı $\times$ Hedef Kritikliği)** seçilmiştir.

* **Neden Seçildi?** 
  Saldırı grafiği analizinde amaç yalnızca teorik en yüksek zafiyeti bulmak değil, bir saldırganın sistemin kritik bileşenine (örn. `node_target_admin` veya `node_target_leak`) gerçekte ne kadar rahat ve olası bir yolla ulaşabileceğini saptamaktır. Yöntem B, olasılık zincirini hesaba katarak güvenlik ekiplerine gerçekçi bir önceliklendirme sunar.

---

## 3. paths.json Verilerine Göre Örnek Yollar Üzerinde Elle Hesaplama

Varsayılan parametreler:
* **Hedef Kritiklik Skoru ($C_{\text{target}}$):** 10.0 (En yüksek kritiklik)
* **Olasılık Değerleri ($P_i$):** 0.0 ile 1.0 arasında normalize edilmiş sömürü olasılığı.

### Örnek Yol 1 (Kısa Yol - Uzunluk: 2)
* **Path Verisi:** `["node_entry_login", "V001", "node_target_admin"]`
* **Adım / Zafiyet:** `V001`
* **Varsayılan Sömürü Olasılığı:** $P_{\text{V001}} = 0.70$
* **Hesaplama:**
  $$\text{Risk} = (0.70) \times 10.0 = \mathbf{7.00}$$

### Örnek Yol 2 (Çok Adımlı Zincirleme Yol - Uzunluk: 3)
* **Path Verisi:** `["node_entry_api", "V002", "V025", "node_target_leak"]`
* **Adımlar / Zafiyetler:** `V002` $\rightarrow$ `V025`
* **Varsayılan Sömürü Olasılıkları:** $P_{\text{V002}} = 0.40$, $P_{\text{V025}} = 0.50$
* **Hesaplama:**
  $$\text{Risk} = (0.40 \times 0.50) \times 10.0 = 0.20 \times 10.0 = \mathbf{2.00}$$

### Örnek Yol 3 (Alternatif Kısa Yol - Uzunluk: 2)
* **Path Verisi:** `["node_entry_search", "V012", "node_target_account_takeover"]`
* **Adım / Zafiyet:** `V012`
* **Varsayılan Sömürü Olasılığı:** $P_{\text{V012}} = 0.30$
* **Hesaplama:**
  $$\text{Risk} = (0.30) \times 10.0 = \mathbf{3.00}$$

---

## 4. Sonuç
Bu metodoloji sayesinde `paths.json` içerisindeki tüm yollar sayısal olarak sıralanmakte; en yüksek riskli yollar güvenlik düzeltmeleri için öncelikli hedef haline getirilmektedir.