import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { OcsfDataGeneratorService } from '../../services/ocsf-data-generator.service';
import { GraphDataService } from '../../services/graph-data.service';
import * as OCSF from '@models/ocsf';
import { saveAs } from 'file-saver';
import { TranslateModule } from '@ngx-translate/core';

interface OcsfClassGroup {
  category: string;
  classes: { name: string, uid: OCSF.OcsfClassUid }[];
}

interface Scenario {
  id: string;
  name: string;
}

@Component({
  selector: 'app-data-generator',
  standalone: true,
  imports: [CommonModule, FormsModule, TranslateModule, RouterLink],
  templateUrl: './data-generator.page.html',
  styleUrls: ['./data-generator.page.scss']
})
export class DataGeneratorPage implements OnInit {

  // Genel State
  isLoading: boolean = false;
  generatedData: OCSF.OcsfEvent[] = [];
  generationTime: number = 0;
  message: string = '';
  messageType: 'success' | 'danger' | '' = '';
  
  // Üretim Modu
  generationMode: 'single' | 'scenario' = 'single';

  // Tekil Sınıf Modu State
  ocsfClassGroups: OcsfClassGroup[] = [];
  selectedClassUid: OCSF.OcsfClassUid = OCSF.OcsfClassUid.FILE_SYSTEM_ACTIVITY;
  
  // Senaryo Modu State
  scenarios: Scenario[] = [
    { id: 'ransomware', name: 'Fidye Yazılımı Saldırısı (Ransomware Attack)' },
    { id: 'phishing', name: 'Kimlik Avı Saldırısı (Phishing Attack)' },
    { id: 'data_infiltration', name: 'Veri Sızdırma (Data Infiltration)' },
  ];
  selectedScenarioId: string = 'ransomware';

  // Ortak State
  numberOfRecords: number = 10;
  
  // İlerleme takibi için
  progressMessage: string = '';

  constructor(
    private ocsfDataGenerator: OcsfDataGeneratorService,
    private graphDataService: GraphDataService
  ) { }

  ngOnInit(): void {
    this.initializeOcsfClasses();
  }

  /**
   * @description Kullanıcının ayarlarına göre test verisi üretme işlemini başlatır.
   * Veriyi parçalar halinde alarak arayüzün donmasını engeller.
   */  
  generateTestData(): void {
    this.isLoading = true;
    this.generatedData = [];
    this.message = '';
    this.progressMessage = 'Veri üretimi başlatılıyor...';
    const startTime = performance.now();

    const payload = this.generationMode === 'single'
      ? { classUid: this.selectedClassUid, count: this.numberOfRecords }
      : { scenarioId: this.selectedScenarioId, count: this.numberOfRecords };

    this.ocsfDataGenerator.generateData(payload).subscribe({
      next: (chunk: OCSF.OcsfEvent[]) => {
        // Her gelen veri parçasını ana diziye ekle
        this.generatedData.push(...chunk);
        // İlerleme mesajını güncelle
        this.progressMessage = `${this.generatedData.length} / ${this.numberOfRecords} kayıt üretildi...`;
      },
      error: (err: any) => {
        console.error('Veri üretilirken hata oluştu:', err);
        this.message = 'Veri üretilirken bir hata oluştu: ' + err.message;
        this.messageType = 'danger';
        this.isLoading = false;
        this.progressMessage = '';
      },
      complete: () => {
        // Tüm parçalar geldiğinde ve işlem bittiğinde çalışır
        this.graphDataService.updateEvents(this.generatedData);
        
        const endTime = performance.now();
        this.generationTime = parseFloat(((endTime - startTime) / 1000).toFixed(2));
        this.message = `${this.generatedData.length} kayıt ${this.generationTime} saniyede başarıyla üretildi.`;
        this.messageType = 'success';
        this.isLoading = false;
        this.progressMessage = ''; // İşlem bitince ilerleme mesajını temizle
      }
    });
  }

  downloadJson(): void {
    if (this.generatedData.length === 0) return;
    const json = JSON.stringify(this.generatedData, null, 2);
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
    const fileName = this.generationMode === 'single'
      ? `ocsf_class_${this.selectedClassUid}_${this.numberOfRecords}_records.json`
      : `ocsf_scenario_${this.selectedScenarioId}_${this.numberOfRecords}_events.json`;
    saveAs(blob, fileName);
  }

  /**
   * @private
   * @description OCSF sınıflarını enum'dan okur, kategorilere ayırır ve `ocsfClassGroups` dizisini doldurur.
   */
  private initializeOcsfClasses(): void {
    const classList = Object.keys(OCSF.OcsfClassUid)
      .filter(key => !isNaN(Number(OCSF.OcsfClassUid[key as any])))
      .map(key => {
        const uid = OCSF.OcsfClassUid[key as keyof typeof OCSF.OcsfClassUid] as OCSF.OcsfClassUid;
        const name = `${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} (${uid})`;
        return { name, uid };
      });

      // Sınıfları kategorilerine göre grupla.
    const groups: { [key: string]: { name: string, uid: OCSF.OcsfClassUid }[] } = {};
    for (const ocsfClass of classList) {
        const categoryName = this.getCategoryNameForClass(ocsfClass.uid);
        if (!groups[categoryName]) {
            groups[categoryName] = [];
        }
        groups[categoryName].push(ocsfClass);
    }

    // Gruplanmış veriyi bileşenin kullanacağı formata dönüştür.
    this.ocsfClassGroups = Object.keys(groups).map(category => ({
        category,
        classes: groups[category].sort((a,b) => a.name.localeCompare(b.name)) 
    }));

    this.ocsfClassGroups.sort((a, b) => {
        const numA = parseInt(a.category.match(/\[(\d+)\]/)?.[1] || '99', 10);
        const numB = parseInt(b.category.match(/\[(\d+)\]/)?.[1] || '99', 10);
        return numA - numB;
    });
  }

  private getCategoryNameForClass(classUid: OCSF.OcsfClassUid): string {
    const uidStr = classUid.toString();
    if (uidStr.startsWith('1')) return 'System Activity [1]';
    if (uidStr.startsWith('2')) return 'Findings [2]';
    if (uidStr.startsWith('3')) return 'Identity & Access Management [3]';
    if (uidStr.startsWith('4')) return 'Network Activity [4]';
    if (uidStr.startsWith('5')) return 'Discovery [5]';
    if (uidStr.startsWith('6')) return 'Application Activity [6]';
    if (uidStr.startsWith('7')) return 'Remediation [7]';
    if (uidStr.startsWith('8')) return 'Unmanned Systems [8]';
    return 'Other';
  }
}
