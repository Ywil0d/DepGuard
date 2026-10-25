# 1. Araştırmanın Amacı

Bu araştırmanın amacı, açık kaynaklı Python projelerinde kullanılan paket sürümlerini inceleyerek bu sürümlerle ilişkili bilinen güvenlik açıklarını belirlemek ve güvenlik riskiyle ilişkili göstergeleri karşılaştırmalı olarak analiz etmektir.

Araştırmada paketlerin sürüm yaşı, bilinen güvenlik açığı sayısı ve mevcut olduğu durumlarda açıklıkların ciddiyet düzeyi değerlendirilecektir. DepGuard, bu bilgileri toplamak, düzenlemek ve analiz etmek amacıyla geliştirilecek bir Python araştırma prototipidir.

Araştırma; paket sürümünün eski olmasının tek başına güvenlik açığı bulunduğunu göstermediği ve bilinen bir güvenlik açığı kaydına rastlanmamasının paketin tamamen güvenli olduğunu kanıtlamadığı varsayımlarını dikkate alarak yürütülecektir.

Proje kapsamında, açık kaynak Python projeleri ve bu projelerde kullanılan paket sürümleri incelenecektir. İhtiyaç duyulan paket ve sürüm bilgileri PyPI API, bilinen güvenlik açıkları ise OSV.dev API üzerinden elde edilecektir. Toplanan veriler eşleştirilerek her paket sürümü için belirlenen bu üç temel risk göstergesi hesaplanacaktır. Elde edilen veriler analiz edilip tablo ve özet sonuçlar hâlinde sunulacak; veri kaynakları, kullanılan yöntem ve araştırmanın sınırlılıkları GitHub deposunda belgelenecektir.

Veri toplama sürecinin mümkün olduğunca otomatikleştirilmesi, eksik veya yinelenen kayıtların kontrol edilmesi ve analiz sonuçlarının grafiklerle desteklenmesi hedeflenmektedir. Paketler arasındaki risk göstergeleri karşılaştırılacak ve uygun durumlarda bu göstergeler arasındaki ilişkiler incelenecektir. Zaman ve kaynak yeterli olduğu takdirde, birden fazla göstergeyi birleştiren basit bir risk puanı oluşturulması ve sonuçların CSV formatında dışa aktarılması da planlanmaktadır.

# 2. Araştırma Sorusu

Açık kaynaklı Python projelerinde kullanılan paket sürümlerinin yaşı ve bu sürümlerle ilişkili bilinen güvenlik açıkları, paketlerin güvenlik riskini değerlendirmek amacıyla nasıl analiz edilebilir?
Alt Araştırma Soruları

    İncelenen paket sürümlerinin yaşları nasıl bir dağılım göstermektedir?

    Paket sürümleri arasında bilinen güvenlik açığı sayısı bakımından ne gibi farklılıklar bulunmaktadır?

    Güvenlik açıklarının ciddiyet bilgileri mevcut olduğunda bu bilgiler nasıl karşılaştırılabilir?

    Sürüm yaşı ve güvenlik açığı göstergelerine dayalı sıralamalar arasında nasıl farklılıklar bulunmaktadır?

# 3. Araştırma Yöntemi

Araştırmada nicel, betimsel ve karşılaştırmalı araştırma yaklaşımı kullanılacaktır.

Veriler, kamuya açık GitHub projeleri, OSV.dev güvenlik açığı kayıtları ve PyPI paket bilgileri üzerinden elde edilecektir. Toplanan bilgiler düzenlenerek paket sürümleri ile güvenlik açığı kayıtları eşleştirilecek ve uygun analiz yöntemleriyle incelenecektir.

Araştırma süreci şu aşamalardan oluşacaktır:

    İncelenecek açık kaynaklı Python projelerinin belirlenmesi.

    Projelerde kullanılan paket ve sürüm bilgilerinin çıkarılması.

    Paket bilgileri ile PyPI üzerinden erişilebilen sürüm bilgilerinin eşleştirilmesi.

    OSV.dev API aracılığıyla bilinen güvenlik açığı kayıtlarının sorgulanması.

    Gerekli durumlarda GitHub üzerinden ek depo ve güvenlik danışmanlığı bilgilerinin incelenmesi.

    Verilerin temizlenmesi, karşılaştırılması ve analiz edilmesi.

    Bulguların tablolar ve grafiklerle raporlanması.

# 4. Veri Kaynakları ve Teknolojiler
## 4.1. OSV.dev API

OSV.dev, paket ekosistemleri ve sürümlerle ilişkili bilinen güvenlik açıklarını sorgulamak amacıyla kullanılacaktır. Elde edilen kayıtlar, incelenen paket sürümleriyle ilişkileri bakımından değerlendirilecektir.
## 4.2. PyPI API

PyPI API, Python paketlerine ve sürümlerine ilişkin bilgileri elde etmek, erişilebilir yayın tarihlerini incelemek ve paket bilgilerini doğrulamak amacıyla kullanılacaktır.
## 4.3. GitHub açık kaynak projeleri

GitHub üzerinde bulunan kamuya açık Python projeleri, araştırmanın örneklem kaynağını oluşturacaktır. Projelerin paket bildirimleri ve erişilebilir sürüm bilgileri incelenecektir.
## 4.4. Kullanılacak teknolojiler

    Python: Veri toplama, veri işleme ve analiz işlemleri.

    OSV.dev API: Bilinen güvenlik açıklarının sorgulanması.

    PyPI API: Paket ve sürüm bilgilerinin elde edilmesi.

    GitHub REST API: Proje ve depo bilgilerinin elde edilmesi.

Bu bölüm, araştırmada kullanılması planlanan teknolojileri açıklamaktadır. Gerçek uygulama durumu ve kullanılan uç noktalar, geliştirme sürecinde belgelenecektir.
# 5. Örneklem Seçimi

Araştırmada kamuya açık GitHub depolarında bulunan Python projeleri incelenecektir. Başlangıçta 20–30 benzersiz paket-sürüm kaydının değerlendirilmesi hedeflenmektedir.

Örneklem seçilirken aşağıdaki ölçütler dikkate alınacaktır:

    Projenin kamuya açık olması.

    Projenin Python kullanması.

    Paket adının belirlenebilmesi.

    İncelenen sürümün güvenilir bir kaynaktan doğrulanabilmesi.

    Paket sürümünün güvenlik kayıtlarıyla karşılaştırılabilmesi.

Sürüm bilgisi doğrulanamayan veya güvenilir biçimde eşleştirilemeyen kayıtlar ayrıca işaretlenecektir. Nihai örneklem büyüklüğü, veri toplama ve doğrulama işlemleri tamamlandıktan sonra raporlanacaktır.
# 6. Değişkenler ve Ölçüm Yöntemleri
## 6.1. Paket sürüm yaşı

Paket sürümünün yayın tarihi ile veri toplama tarihi arasındaki gün sayısı olarak hesaplanacaktır. Yayın tarihi doğrulanamayan kayıtlar eksik veri olarak işaretlenecektir.
## 6.2. Bilinen güvenlik açığı sayısı

İncelenen paket sürümüyle ilişkili olduğu doğrulanan benzersiz güvenlik açığı kayıtlarının sayısı hesaplanacaktır. Güvenlik açığının ilgili sürümü etkileyip etkilemediği, kaynakta bulunan etkilenen sürüm bilgileri dikkate alınarak değerlendirilecektir.
## 6.3. Güvenlik açığı ciddiyeti

Güvenlik açığı kayıtlarında mevcutsa CVSS puanı veya kaynakta belirtilen ciddiyet düzeyi kullanılacaktır. Ciddiyet bilgisi bulunmayan kayıtlar sıfır ciddiyetli kabul edilmeyecek, eksik bilgi olarak işaretlenecektir.
## 6.4. Veri kaynağı ve doğrulama bilgisi

Her kayıt için kullanılan veri kaynağı ve mümkün olduğunda ilgili güvenlik açığı kimliği tutulacaktır. Aynı güvenlik açığının farklı kaynaklarda tekrar yer alması durumunda mükerrer sayımı önlemek için kayıtlar kontrol edilecektir.
# 7. Veri Analizi

Veri toplama tamamlandıktan sonra veriler temizlenecek, yinelenen kayıtlar kontrol edilecek ve eksik bilgiler belgelenecektir.

Analiz kapsamında:

    Paket sürüm yaşlarının dağılımı incelenecektir.

    Bilinen güvenlik açığı sayıları paket sürümleri arasında karşılaştırılacaktır.

    Mevcut ciddiyet bilgilerinin dağılımı değerlendirilecektir.

    Sürüm yaşı ve güvenlik açığı göstergelerine göre elde edilen sıralamalar karşılaştırılacaktır.

Veri miktarı ve uygunluğu yeterliyse sıralamalar arasındaki ilişkiyi değerlendirmek için Spearman sıra korelasyonu kullanılabilecektir. Bu analizin uygulanıp uygulanmayacağı, veri setinin yapısı ve eksik verilerin durumu incelendikten sonra belirlenecektir.

Birleşik risk puanı oluşturulması durumunda puanlama formülü, değişkenlerin ağırlıkları ve normalleştirme yöntemi açıkça belgelenecektir. Birleşik puan, yöntemi tanımlanmadan doğrulanmış bir güvenlik ölçüsü olarak sunulmayacaktır.
# 8. Geçerlilik Tehditleri ve Sınırlılıklar

Araştırmanın sonuçları aşağıdaki sınırlılıklar çerçevesinde yorumlanacaktır:

    Kullanılan veri kaynakları, henüz bildirilmemiş veya veri tabanlarına eklenmemiş güvenlik açıklarını kapsamayabilir.

    Eski bir paket sürümü tek başına güvenlik açığı bulunduğunu göstermez.

    Güvenlik açığı kaydının bulunmaması, paketin tamamen güvenli olduğu anlamına gelmez.

    Proje dosyalarında bildirilen sürüm, çalışma ortamında kurulu olan sürümle aynı olmayabilir.

    Sürüm eşleştirmeleri, eksik ciddiyet bilgileri ve veri kaynağı kapsamı sonuçları etkileyebilir.

    Sınırlı sayıdaki paket-sürüm kaydı, bütün Python ekosistemini temsil etmeyebilir.

    Göstergeler arasındaki ilişki, doğrudan bir neden-sonuç ilişkisi olduğunu kanıtlamaz.

# 9. Yeniden Üretilebilirlik

Araştırmanın yeniden üretilebilirliğini desteklemek amacıyla veri kaynakları, veri toplama tarihi, sorgu ölçütleri, veri temizleme kararları ve analiz adımları belgelenecektir.

Uygulama geliştikçe kaynak kodu, kullanım talimatları, uygun örnek veri ve doğrulanmış analiz çıktıları GitHub deposuna eklenecektir. Gerçekleştirilmeyen işlemler veya elde edilmeyen sonuçlar tamamlanmış çalışma olarak raporlanmayacaktır.
# 10. Mevcut Durum

Bu belge araştırmanın planlanan yöntemini ve tasarımını açıklamaktadır. Veri toplama, kod geliştirme ve analiz işlemleri tamamlandıkça ilgili bölümler gerçek uygulama sonuçlarına göre güncellenecektir.
