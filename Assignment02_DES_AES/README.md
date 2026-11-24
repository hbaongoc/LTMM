# Assignment 02 - DES và AES-128

## 1. Nội dung bài tập

- Cài đặt thuật toán mã hóa và giải mã DES, AES-128 bằng Python.
- In các giá trị trung gian trong từng bước của thuật toán.
- Kiểm tra kết quả bằng test vector.

## 2. Cấu trúc thư mục

- `des/`: Code thuật toán DES.
- `aes/`: Code thuật toán AES-128.
- `tests/`: Code kiểm thử.
- `results/`: Kết quả chạy chương trình.

## 3. Kiểm thử DES

| Thông số | Giá trị HEX |
|---|---|
| Bản rõ | 0123456789ABCDEF |
| Khóa | 133457799BBCDFF1 |
| Bản mã | 85E813540F0AB405 |
| Kết quả giải mã | 0123456789ABCDEF |

Test vector DES được bổ sung để kiểm tra thuật toán.

## 4. Cách chạy

Chạy các lệnh sau tại thư mục `Assignment01_DES_AES`.

**Mã hóa DES:**

```bash
python -c "from des.des import des_encrypt; des_encrypt('0123456789ABCDEF', '133457799BBCDFF1', verbose=True)"
```

**Giải mã DES:**

```bash
python -c "from des.des import des_decrypt; des_decrypt('85E813540F0AB405', '133457799BBCDFF1', verbose=True)"
```

**Chạy kiểm thử:**

```bash
python -m unittest discover -s tests -p "test_des.py" -v
```

## 5. Kết quả

DES đã chạy thành công 10/10 test case.

- [Kết quả mã hóa](results/des_encryption.txt)
- [Kết quả giải mã](results/des_decryption.txt)
- [Kết quả kiểm thử](results/des_test_results.txt)