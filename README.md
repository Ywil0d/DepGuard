# DepGuard

**Python projelerindeki paket bağımlılıklarının güvenlik risklerini inceleyen bir araştırma projesi.**

DepGuard, GitHub'daki açık kaynak Python projelerinin kullandığı paketleri analiz ederek bilinen güvenlik açıklarını belirlemeyi ve paketlerin risk göstergelerini karşılaştırmayı amaçlar.

##  Projenin Amacı

- Python projelerindeki paket ve sürüm bilgilerini toplamak.
- Paketleri bilinen güvenlik açıklarıyla eşleştirmek.
- Sürüm eskiliği, açıklık sayısı ve açıklık ciddiyetini karşılaştırmak.
- Sonuçları tablolar ve grafiklerle anlaşılır biçimde sunmak.

##  Nasıl Çalışır?

1. GitHub projelerinin bağımlılık dosyaları incelenir.
2. Paket ve sürüm bilgileri PyPI üzerinden kontrol edilir.
3. Bilinen güvenlik açıkları OSV.dev üzerinden sorgulanır.
4. Elde edilen veriler analiz edilerek risk göstergeleri karşılaştırılır.

##  Kullanılan Teknolojiler

- **Python:** Veri toplama ve analiz
- **OSV.dev:** Güvenlik açığı kayıtları
- **PyPI:** Paket ve sürüm bilgileri
- **Pandas:** Veri işleme
- **Matplotlib:** Grafik oluşturma

## ⚠️ Sınırlılıklar

DepGuard, bilinmeyen güvenlik açıklarını keşfetmez ve bir paketin kesin olarak saldırıya açık olduğunu kanıtlamaz. Eski sürüm kullanılması tek başına güvenlik açığı olduğu anlamına gelmez. Sonuçlar, kamuya açık güvenlik kayıtlarına dayalı risk göstergeleri olarak değerlendirilmelidir.

##  Proje Durumu

Bu proje, Araştırma Yöntem ve Teknikleri dersi kapsamında geliştirilen bir araştırma prototipidir. Veri toplama, analiz ve uygulama sonuçları tamamlandıkça belgelenecektir.
