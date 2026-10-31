# DepGuard

**Python projelerindeki paketlerin güvenlik risklerini inceleyen bir araştırma projesi.**

DepGuard, GitHub'daki açık kaynak Python projelerinin kullandığı paketleri analiz ederek bilinen güvenlik açıklarını belirlemeyi ve paketlerin risk göstergelerini karşılaştırmayı amaçlar.

##  Projenin Amacı

- Python projelerindeki paket ve sürüm bilgilerini toplamak.
- Paketleri bilinen güvenlik açıklarıyla eşleştirmek.
- Sürüm eskiliği, açıklık sayısı ve açıklık ciddiyetini karşılaştırmak.
- Sonuçları tablolar ve grafiklerle anlaşılır biçimde sunmak.

##  Nasıl Çalışır?

1. GitHub projelerinin paket dosyaları incelenir.
2. Paket ve sürüm bilgileri PyPI üzerinden kontrol edilir.
3. Bilinen güvenlik açıkları OSV.dev üzerinden sorgulanır.
4. Elde edilen veriler analiz edilerek risk göstergeleri karşılaştırılır.

##  Kullanılan Teknolojiler

- **Python:** Veri toplama ve analiz
- **OSV.dev:** Güvenlik açığı kayıtları
- **PyPI:** Paket ve sürüm bilgileri
- **Pandas:** Veri işleme
- **Matplotlib:** Grafik oluşturma

## UML Diyagramları

Aşağıdaki diyagramlar, kodlama aşamasından önce sistemin yapısını ve işleyişini modellemek için hazırlanmıştır.

### 1. Use Case Diagram
![Use Case Diagram](docs/uml/01-use-case-diagram.png)

Araştırmacının sistemle yapabileceği işlemleri gösterir: proje seçme, analizi başlatma, karşılaştırma, tablo/grafik oluşturma ve CSV dışa aktarma. GitHub, PyPI ve OSV.dev harici sistemler olarak gösterilmiştir.

### 2. Activity Diagram
![Activity Diagram](docs/uml/02-activity-diagram.png)

GitHub projelerinin paketlerinin analiz sürecini gösterir: bağımlılık dosyasının alınması, paketlerin PyPI ve OSV.dev ile kontrolü, risk skorunun hesaplanması ve sonuçların tablo/grafik olarak sunulması. Dosyanın bulunamaması ve açık kaydının olup olmaması karar noktalarıdır.

### 3. Class Diagram
![Class Diagram](docs/uml/03-class-diagram.png)

Projenin temel sınıflarını gösterir: Project, Package, Vulnerability, RiskScore; veri toplayan GitHubClient, RequirementsParser, PyPIClient ve OSVClient; analiz yapan RiskAnalyzer; çıktı üreten ReportGenerator.

## ⚠️ Dikkat

DepGuard, bilinmeyen güvenlik açıklarını keşfetmez ve bir paketin kesin olarak saldırıya açık olduğunu kanıtlamaz. Eski sürüm kullanılması tek başına güvenlik açığı olduğu anlamına gelmez. Sonuçlar, kamuya açık güvenlik kayıtlarına dayalı risk göstergeleri olarak değerlendirilmelidir.

##  Proje Durumu

Bu proje, Araştırma Yöntem ve Teknikleri dersi kapsamında geliştirilen bir araştırma prototipidir. Veri toplama, analiz ve uygulama sonuçları tamamlandıkça belgelenecektir.
