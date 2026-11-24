# Assignment 02 – DES & AES-128

## 1. Mục tiêu

Cài đặt thuật toán mã hóa và giải mã DES, AES-128 bằng Python.

- Tự xây dựng các phép biến đổi của từng thuật toán.
- In giá trị trung gian tại từng vòng mã hóa và giải mã.
- Kiểm tra kết quả bằng các test vector.
- Xây dựng bộ kiểm thử tự động và lưu kết quả thực thi.

## 2. Cấu trúc thư mục

```
Assignment02_DES_AES/
├── des/
│   ├── __init__.py
│   ├── tables.py
│   ├── key_schedule.py
│   ├── feistel.py
│   └── des.py
├── aes/
│   ├── __init__.py
│   ├── gf.py
│   ├── sbox.py
│   ├── transformations.py
│   ├── key_expansion.py
│   └── aes.py
├── tests/
│   ├── test_des.py
│   └── test_aes.py
├── results/
└── README.md
```

## 3. Thuật toán DES

DES sử dụng khối dữ liệu 64 bit, khóa 64 bit (56 bit hiệu dụng) và thực hiện 16 vòng Feistel.

Các chức năng đã cài đặt:

- Hoán vị IP và FP.
- Sinh 16 khóa vòng.
- Hàm Feistel: Expansion, XOR, S-box và P-box.
- Mã hóa và giải mã DES.
- In giá trị trung gian của từng vòng.

### Test vector DES

| Tham số | Giá trị (HEX) |
|---|---|
| Plaintext | `0123456789ABCDEF` |
| Key | `133457799BBCDFF1` |
| Ciphertext | `85E813540F0AB405` |

### Chạy mã hóa

```bash
python -c "from des.des import des_encrypt; des_encrypt('0123456789ABCDEF','133457799BBCDFF1',verbose=True)"
```

### Chạy giải mã

```bash
python -c "from des.des import des_decrypt; des_decrypt('85E813540F0AB405','133457799BBCDFF1',verbose=True)"
```

## 4. Thuật toán AES-128

AES-128 sử dụng khối dữ liệu 128 bit, khóa 128 bit và thực hiện 10 vòng mã hóa.

Các chức năng đã cài đặt:

- Các phép toán trên trường GF(2⁸).
- Sinh S-box và Inverse S-box.
- SubBytes và InvSubBytes.
- ShiftRows và InvShiftRows.
- MixColumns và InvMixColumns.
- AddRoundKey.
- Key Expansion.
- Mã hóa và giải mã AES-128.
- In các trạng thái trung gian của từng vòng.

### Test vector AES-128 chuẩn

| Tham số | Giá trị (HEX) |
|---|---|
| Plaintext | `00112233445566778899AABBCCDDEEFF` |
| Key | `000102030405060708090A0B0C0D0E0F` |
| Ciphertext | `69C4E0D86A7B0430D8CDB78070B4C55A` |

### Test vector dựa trên ví dụ trên lớp

| Tham số | Giá trị (HEX) |
|---|---|
| Plaintext | `00000000000000000000000000001111` |
| Key | `00000000000000000000000000000000` |
| Ciphertext | `442758DF6DDA9EDB6BF1468A17B93FE5` |

### Chạy mã hóa

```bash
python -c "from aes.aes import aes_encrypt; aes_encrypt('00112233445566778899AABBCCDDEEFF','000102030405060708090A0B0C0D0E0F',verbose=True)"
```

### Chạy giải mã

```bash
python -c "from aes.aes import aes_decrypt; aes_decrypt('69C4E0D86A7B0430D8CDB78070B4C55A','000102030405060708090A0B0C0D0E0F',verbose=True)"
```

## 5. Kiểm thử

Chạy các lệnh từ thư mục `Assignment02_DES_AES`.

Kiểm thử DES:

```bash
python -m unittest discover -s tests -p "test_des.py" -v
```

Kiểm thử AES-128:

```bash
python -m unittest discover -s tests -p "test_aes.py" -v
```

Kiểm thử toàn bộ:

```bash
python -m unittest discover -s tests -v
```

### Kết quả kiểm thử

| Thuật toán | Số test case | Kết quả |
|---|---:|---|
| DES | 10 | PASS |
| AES-128 | 18 | PASS |
| Tổng cộng | 28 | PASS |

## 6. Kết quả thực thi

### DES

- [Kết quả mã hóa DES](results/des_encryption.txt)
- [Kết quả giải mã DES](results/des_decryption.txt)
- [Kết quả kiểm thử DES](results/des_test_results.txt)

### AES-128

- [Kết quả mã hóa AES](results/aes_encryption.txt)
- [Kết quả giải mã AES](results/aes_decryption.txt)
- [Mã hóa ví dụ trên lớp](results/aes_class_encryption.txt)
- [Giải mã ví dụ trên lớp](results/aes_class_decryption.txt)
- [Kết quả Key Expansion](results/aes_key_expansion.txt)
- [Bảng S-box và Inverse S-box](results/aes_sbox.txt)
- [Kết quả kiểm thử AES](results/aes_test_results.txt)

### Tổng hợp

- [Kết quả kiểm thử toàn bộ bài tập](results/all_test_results.txt)

## 7. Môi trường thực hiện

- Ngôn ngữ: Python 3.
- Công cụ: Visual Studio Code.
- Kiểm thử: unittest.
- Quản lý mã nguồn: Git và GitHub.
- Không sử dụng thư viện mã hóa có sẵn trong phần cài đặt thuật toán.