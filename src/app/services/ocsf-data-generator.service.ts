import { Injectable } from '@angular/core';
import * as OCSF from '@models/ocsf';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class OcsfDataGeneratorService {
  private worker: Worker;

  constructor() {
    this.worker = new Worker(new URL('../workers/data-generator.worker', import.meta.url), { type: 'module' });
  }

  /**
   * Veri üretme işlemini başlatır ve üretilen veriyi parçalar halinde bir Observable olarak döndürür.
   * @param payload Üretim için gerekli olan sınıf UID'si veya senaryo ID'si ve kayıt sayısı.
   * @returns OCSF olay dizisi parçalarını yayan bir Observable.
   */
  generateData(payload: { classUid?: OCSF.OcsfClassUid, scenarioId?: string, count: number }): Observable<OCSF.OcsfEvent[]> {
    return new Observable(observer => {
      this.worker.onmessage = ({ data }) => {
        // Gelen mesajın tipine göre işlem yap
        if (data.type === 'data') {
          // Veri parçası geldi, observer'a gönder
          observer.next(data.payload as OCSF.OcsfEvent[]);
        } else if (data.type === 'done') {
          // İşlem bitti, observable'ı tamamla
          observer.complete();
        } else if (data.type === 'error') {
          // Hata oluştu, observable'a hata gönder
          console.error("Error message from data-generator.worker:", data.payload);
          observer.error(new Error(data.payload));
        }
      };

      this.worker.onerror = (error) => {
        console.error("Critical error from data-generator.worker:", error);
        observer.error(error);
      };

      // Worker'a mesaj göndererek işlemi başlat
      this.worker.postMessage(payload);

      // Observable'dan çıkıldığında (unsubscribe) worker'ı sonlandırmak için bir temizleme fonksiyonu döndür.
      // Bu, bileşen yok edildiğinde gereksiz worker işlemlerini önler.
      return () => {
      };
    });
  }
}
