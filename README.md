# OCSF Telemetri Analiz ve Simülasyon Platformu

Bu proje, **Open Cybersecurity Schema Framework (OCSF)** formatındaki güvenlik telemetri verilerini üretmek, analiz etmek ve görselleştirmek için geliştirilmiş modern bir web uygulamasıdır.  
Siber güvenlik analistleri, araştırmacılar ve geliştiriciler için OCSF standardını anlama, test etme ve kullanma süreçlerini kolaylaştıran zengin bir araç seti sunar.

---

## Temel Özellikler

Uygulama üç ana modülden oluşmaktadır:

---

### 1. Telemetri Analizi (Telemetry Analysis)

Bu modül, mevcut OCSF verilerinizi yükleyerek interaktif panolar üzerinde derinlemesine analiz yapmanızı sağlar.

#### Özellikler:
- **Veri Yükleme:** JSON formatındaki OCSF log dosyalarınızı sürükle-bırak veya dosya seçici ile kolayca yükleyin.
- **Dinamik Filtreleme:** Verileri olay sınıfı, kullanıcı, önem seviyesi ve tarih aralığı gibi kriterlere göre anlık olarak filtreleyin.
- **Gelişmiş Görselleştirmeler:**
  - **Olay Hacmi Grafiği:** Zaman içindeki olay yoğunluğunu önem seviyesi bazında gösterir.
  - **Kategori Dağılımı:** Olayların OCSF kategorilerine göre dağılımını pasta grafiği ile sunar.
  - **Haftalık Isı Haritası:** Haftanın hangi gün ve saatlerinde olay yoğunluğunun arttığını gösterir.
  - **En Aktif Kullanıcılar:** En çok olay üreten kullanıcıları listeler.
- **Raporlama ve Dışa Aktarma:** Analiz sonuçlarını PDF olarak raporlayın veya ham verileri JSON/CSV formatında indirin.

---

### 2. Veri Üretici (Data Generator)

Gerçekçi ve çeşitli OCSF verileri üretmek için güçlü bir simülasyon aracıdır.

#### Üretim Modları:
- **Tekil Sınıf Modu:** Belirli bir OCSF olay sınıfından (örneğin, *File System Activity*) istediğiniz sayıda rastgele olay üretin.
- **Senaryo Modu:** Önceden tanımlanmış siber saldırı senaryolarını (örn. Fidye Yazılımı, Kimlik Avı, Veri Sızdırma) simüle edin.

#### Diğer Özellikler:
- **Yüksek Performans:** Milyonlarca kaydı bile Web Worker ile hızlı ve akıcı şekilde üretir.
- **Veri İndirme:** Üretilen verileri anında JSON formatında indirin.

---

### 3. İlişki Grafiği (Graph Visualizer)

Üretilen veya yüklenen verilerdeki varlıklar (kullanıcı, process, dosya, IP adresi vb.) arasındaki ilişkileri görsel olarak keşfedin.

#### Özellikler:
- **Otomatik İlişki Haritalama:** Olay verilerinden varlıkları ve aralarındaki bağlantıları çıkarır.
- **İnteraktif Keşif:** Düğümlere tıklayarak detayları görüntüleyin, fare ile üzerine gelerek bağlantılı varlıkları vurgulayın.
- **Dinamik Filtreleme:** Grafiği düğüm tiplerine göre filtreleyerek karmaşıklığı azaltın.
- **Performans Optimizasyonu:** Büyük veri setlerinde akıcı bir deneyim için sadece belirli düğümleri gösterir.

---

## Teknik Yapı ve Kullanılan Teknolojiler

- **Frontend:** Angular 20, TypeScript  
- **Grafik Kütüphaneleri:**
  - `ng2-charts` (Chart.js) – Pano grafikleri
  - `ngx-echarts` (Apache ECharts) – Isı haritası
  - `ngx-graph` (D3.js) – İlişki grafiği
- **Asenkron İşlemler:** Web Workers (UI donmasını önlemek için)
- **Uluslararasılaştırma:** `ngx-translate` (TR / EN destekli)
- **Tema ve Stil:** SCSS, Bootstrap 5, CSS değişkenleri ile dinamik temalar (Light, Dark, Blue, Green)
- **Yardımcı Kütüphaneler:** `file-saver`, `pdfmake`

---

## Kurulum ve Başlatma

Projeyi yerel makinenizde çalıştırmak için şu adımları izleyin:

1. Projeyi Klonlayın
```bash
git clone
```

2. Bağımlılıkları Yükleyin
```bash
npm install
```

3. Geliştirme Sunucusunu Başlatın
```bash
ng serve
```

4. Tarayıcınızda http://localhost:4200 adresine gidin.


## Kullanım Akışı

1. Veri Üretin
- `Data Generator` sayfasına gidin.
    - Bir senaryo veya tekil bir OCSF sınıfı seçin.
    - Üretilecek kayıt sayısını belirleyin ve `Veri Üret` butonuna tıklayın.

2. İlişkileri Keşfedin
- Veri ürettikten sonra `Grafiği Görüntüle` butonuna tıklayarak `Graph Visualizer` sayfasına geçin.
    - Varlıklar arasındaki ilişkileri interaktif olarak inceleyin.
    - Düğüm filtreleme ile belirli türleri izole edin.

3. Analiz Edin
- `Telemetry` sayfasına gidin.
    - Kendi OCSF JSON dosyanızı yükleyin veya daha önce ürettiğiniz verileri analiz edin.
    - Tarih aralığı, kullanıcı, önem seviyesi gibi filtreleri kullanın.
    - Grafiklerle olayları analiz edin.

4. Raporlayın
    - Panodaki analizleri PDF formatında dışa aktarın.
    - Olay verilerini JSON veya CSV formatlarında indirin.