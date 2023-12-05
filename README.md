# Enkripsi Deskripsi File Dengan Kata Sandi

Skrip ini menyediakan mekanisme enkripsi dan dekripsi sederhana menggunakan kata sandi. Skrip ini menggunakan algoritma enkripsi simetris Fernet dari pustaka cryptography.

## Fitur
- Derivasi kunci yang aman menggunakan Crypthograhi.
- Enkripsi dan dekripsi file yang dilindungi oleh kata sandi.
- Pilihan untuk mengenkripsi/mendekripsi file individu atau seluruh folder.
- Generasi otomatis dan penyimpanan salt unik untuk derivasi kunci.
- Scan Folder dan File

## Penggunaan
1. pip install -r requirements.txt
2. Enkripsi File atau Folder: `python script.py <path_ke_file_atau_folder> -e`
3. Dekripsi File atau Folder: `python script.py <path_ke_file_atau_folder> -d`
4. Pindai dan Tampilkan Folder yang Tersedia: `python script.py --scan`
5. Tentukan Ukuran Salt (Opsional): `python script.py <path_ke_file_atau_folder> -e -s <ukuran_salt>`

## Contoh
1. Enkripsi sebuah file: `python script.py contoh.txt -e`
2. Dekripsi sebuah folder: `python script.py /path/ke/folder -d`

## Catatan
Pastikan untuk menjaga kata sandi Anda dengan aman, karena digunakan untuk derivasi kunci. Dan juga skrip ini bisa menjadi awal dari penyerangan **RansomWare** yang membuat data korban menjadi terkunci dan mereka diperas oleh penyerang.
### Pastikan jalankan kode ini pada sistem yang memiliki Izin😁

