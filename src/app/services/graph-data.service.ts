import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import * as OCSF from '@models/ocsf';

@Injectable({
  providedIn: 'root'
})
export class GraphDataService {
  private eventsSource = new BehaviorSubject<OCSF.OcsfEvent[]>([]);
  
  // Diğer bileşenlerin abone olabileceği observable.
  currentEvents$ = this.eventsSource.asObservable();

  constructor() { }

  /**
   * Yeni üretilen olay verisini servise gönderir ve abone olan tüm bileşenleri bilgilendirir.
   * @param events Veri üretici sayfasından gelen OCSF olayları.
   */
  updateEvents(events: OCSF.OcsfEvent[]): void {
    this.eventsSource.next(events);
  }
}
