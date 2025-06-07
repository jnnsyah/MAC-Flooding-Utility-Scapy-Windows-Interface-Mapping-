MAC Flooding Utility (Scapy + Windows Interface Mapping)

# 🔍 MAC Flooding Utility (Scapy + Windows Interface Mapping)

Tool ini digunakan untuk mengirim frame Ethernet custom ke target MAC address di jaringan lokal, dengan payload yang bisa dikustomisasi ukurannya. Dibuat khusus untuk Windows dan menggunakan Scapy, WMI, dan interface mapping otomatis.

---

## ✨ Fitur

- Deteksi interface jaringan aktif (dengan nama yang ramah untuk user)
- Scan MAC address terdekat dengan metode **ARP Request (aktif)**
- Pilih rentang ukuran payload yang ingin dikirim
- Kirim frame dengan sumber MAC address random (spoofed)

---

## ⚙️ Persyaratan

- Python 3.6+
- Windows OS
- [Scapy](https://scapy.net/)
- [WMI Python Package](https://pypi.org/project/WMI/)

Install dependencies:

```bash
pip install scapy wmi
```

🚀 Cara Pakai
```bash
python mac_flooder.py
```
Langkah-langkah:

1. Pilih interface jaringan yang tersedia
2. Tool akan scan perangkat di jaringan lokal dan menampilkan MAC yang terdeteksi
3. Masukkan target MAC address (akan divalidasi)
4. Masukkan ukuran payload awal, akhir, dan langkah (step)
5. Tool akan mengirim frame-frame secara bertahap ke target MAC

📡 Contoh Output
```
🔍 Available Network Interfaces:
 0: Wi-Fi (Intel(R) Wireless-AC 9560 160MHz)
 1: Ethernet (Realtek PCIe GbE Family Controller)
Select an interface by number: 0

[*] Scanning for nearby MAC addresses on interface Wi-Fi...
[*] Found 5 unique MAC addresses nearby.

Enter the target MAC address (format XX:XX:XX:XX:XX:XX): aa:bb:cc:dd:ee:ff

Specify payload size range (bytes):
Start size (e.g. 10): 10
End size (e.g. 100): 100
Step size (e.g. 10): 10

[*] Starting to send frames on interface Wi-Fi to target MAC aa:bb:cc:dd:ee:ff...
[+] Sent payload size: 10 bytes
[+] Sent payload size: 20 bytes
...
[*] Finished sending packets.
```
