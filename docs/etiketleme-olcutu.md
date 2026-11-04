# Uzman Etiketleme Ölçütü

> **Durum:** K4 onayı bekleyen taslak.

## Amaç ve kapsam

Bu ölçüt, envanterdeki 36 kayda aynı risk sorularını uygulayıp model değerlendirmesinde kullanılacak referans etiketleri tutarlı gerekçelerle üretmek için hazırlanmıştır. Etiket, kaydın bugünkü kanıtlara göre savunma açısından önceliğini ifade eder; bir zafiyetin üretim ortamında kesin olarak sömürülebileceğini veya CVSS puanının doğru olduğunu tek başına kanıtlamaz.

Etiketleme birimi `vuln_id` başına tek envanter kaydıdır. Birden fazla kayıtta aynı paket, CWE veya CVSS bulunması etiketlerin otomatik olarak aynı olmasını gerektirmez; kayıtların etkisi, erişim koşulları ve kanıtı ayrı değerlendirilir.

## Kullanılacak kanıtlar

Her kayıt için mevcut olduğu ölçüde şu alanlar ve kaynaklar birlikte incelenir:

- Etki ve varlığın önemi: `cvss_score`, CVSS vektöründeki C/I/A etkileri, `asset_criticality` ve zafiyet açıklaması.
- Sömürülebilirlik koşulları: `attack_vector`, `attack_complexity`, `auth_required` ve `user_interaction`.
- Olasılık ve erişim: `epss_score`, `exposure`, `entry_point` ve `entry_evidence`.
- Kaynağın sınırları: challenge tanımı, ZAP bulgusu veya Trivy paket/sürüm kaydı; `notes` alanındaki belirsizlikler.

CVSS ve EPSS farklı şeyleri gösterir: CVSS zafiyetin teknik şiddetini, EPSS ise gerçek dünyada sömürülme olasılığına ilişkin tahmini gösterir. İkisi de tek başına nihai etiketi belirlemez. EPSS yoksa veya `bilinmiyor` ise değer uydurulmaz ve kayıt bu yüzden otomatik olarak düşük önceliğe indirilmez.

`dependency` girişi, paketin tarama çıktısında bulunduğunu kanıtlar; zafiyetli kod yolunun uygulamada kullanıldığını veya dışarıdan erişilebilir olduğunu tek başına kanıtlamaz. Bu belirsizlik gerekçede belirtilir. Benzer şekilde, `exposure=internet` değeri tek başına belirli bir bağımlılığın uzaktan sömürülebileceğine kanıt sayılmaz.

## Etiketler

Etiketler en yüksek öncelikten en düşüğe sıralanır. Bir kayıt için aşağıdaki tanımlardan birini karşılayan kanıt varsa o sınıf seçilir; gerekçe, kararı belirleyen kanıtı ve önemli sınırlamaları açıklar.

| Etiket | Karar ölçütü |
|---|---|
| **Kritik** | Kanıtlanan etki, yönetici yetkisi elde edilmesi, sistemin bütünüyle ele geçirilmesi veya hassas verilerin geniş ölçekte açığa çıkması gibi çok ağır bir sonuç doğurabilir; saldırı yolu uygulanabilir ve önemli bir önkoşul ya da koruma engeli gösterilmemiştir. |
| **Yüksek** | Ciddi gizlilik, bütünlük veya kullanılabilirlik etkisi vardır; ancak gerekli kimlik doğrulama, yüksek saldırı karmaşıklığı, kullanıcı etkileşimi, etkinin kapsamı veya erişilebilirliğin doğrulanmamış olması önceliği Kritik seviyesinden ayırır. |
| **Orta** | Etki sınırlı bir hesap, veri kümesi veya işlevle sınırlıdır ya da anlamlı kullanıcı etkileşimi/önkoşullar gerekir. Bulguyu dikkate almak gerekir, ancak mevcut kanıt acil ve geniş kapsamlı bir riski göstermiyordur. |
| **Düşük** | Kanıtlanan sonuç çoğunlukla bilgi açıklama veya savunma derinliğini azaltma gibi sınırlı bir etkidir; doğrudan ve kayda değer bir gizlilik, bütünlük ya da kullanılabilirlik kaybı gösterilmemiştir. |

Bir kayıt için anlamlı bir etki veya sömürülebilirlik kanıtı yoksa etiket tahmin edilmez. Kayıt dışlanmak yerine belirsizlik gerekçeye yazılır ve insan incelemesine bırakılır.

### Sınıfları ayırırken

- Yüksek CVSS tek başına **Kritik** etiketi verdirmez. Kritik için ağır etkinin yanı sıra uygulamaya özgü kanıtla uygulanabilir bir yol da aranır.
- Ciddi bir etki mümkün görünse bile gerekli kimlik doğrulama, yüksek karmaşıklık, kullanıcı etkileşimi veya yalnızca bağımlılık taramasıyla varlığın doğrulanmış olması **Yüksek** ile **Kritik** arasındaki ayrımı etkiler.
- CVSS ile tarayıcı önem derecesi çelişiyorsa ya da sömürü yoluna ilişkin temel varsayım doğrulanmamışsa, bu çelişki gerekçeye yazılır ve etiket kanıttan daha kesin gösterilmez.
- Sınırlı hesap/işlev etkisi veya önemli kanıt belirsizliği **Orta** değerlendirmesini destekleyebilir. Yalnızca bilgi veren ya da savunma derinliği sağlayan bulgular, somut bir etki gösterilmedikçe **Düşük** kalır.

## Her kayıt için karar sırası

1. **Kanıtı netleştir:** Kaydın hangi kaynaktan geldiğini, giriş noktasını ve kanıtın neyi doğrulayıp neyi doğrulamadığını belirle.
2. **Olası sonucu değerlendir:** Gizlilik, bütünlük ve kullanılabilirlik etkisini; hedef varlığın önemini ve etkinin kapsamını incele.
3. **Saldırı koşullarını değerlendir:** Gerekli erişim, karmaşıklık, kullanıcı etkileşimi ve erişilebilirlik kanıtını dikkate al.
4. **Destekleyici puanlara bak:** CVSS ve varsa EPSS değerlerini diğer kanıtlarla birlikte yorumla. Puan ile kanıt çelişiyorsa çelişkiyi gerekçeye yaz; puanı sessizce doğru kabul etme.
5. **Tek bir etiket seç ve gerekçelendir:** Gerekçe, seçilen sınıfı neden uygun bulduğunu ve kararı etkileyen belirsizlikleri kısa ve kayda özel biçimde açıklasın.

Etiket, bir saldırı zincirindeki teorik olasılığa veya CWE adına bakılarak tek başına verilmez. Aynı zincirde bulunmak, kaydın etkisini ya da önceliğini otomatik olarak değiştirmez.



## Etiket CSV biçimi

`ai/expert_labels.csv` şu başlıkları kullanır:

```csv
vuln_id,label,gerekce
```

`label` yalnızca `Kritik`, `Yüksek`, `Orta` veya `Düşük` olabilir. Her `vuln_id` bir kez yer almalı ve her etiketin gerekçesi gözden geçirilebilir kanıta dayanmalıdır.
