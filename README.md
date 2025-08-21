# slopeorfyorf

slopeorfyorf.py — Metasploit-benzeri konsol: yalnızca izinli/pasif-hafif pentest modülleri
Saldırı/istismar YOK. Brute-force/DDoS/Exploit YOK. Eğitim ve güvenli inceleme içindir.

KURULUM:
  pip install requests beautifulsoup4

ÇALIŞTIRMA:
  python slopeorfyorf.py

  KOMUTLAR (MSF tarzı):
  help                     - Komut yardımını göster
  banner                   - Banner yazdır
  show modules             - Modül listesini göster
  use <modül_adı>          - Bir modülü seç
  show options             - (seçili modül için) seçenekleri göster
  set <anahtar> <değer>    - (modül) seçenek ayarla
  unset <anahtar>          - (modül) seçeneği sıfırla
  setg <anahtar> <değer>   - Global seçenek ayarla (örn target, timeout, user_agent)
  unsetg <anahtar>         - Global seçenek sil
  run                      - Seçili modülü çalıştır
  back                     - Modülden çık ve ana menüye dön
  sessions                 - Son bulguların özetini göster
  report json <dosya>      - Son bulguları JSON olarak kaydet
  report html <dosya>      - Son bulguları HTML olarak kaydet
  exit / quit              - Çık
