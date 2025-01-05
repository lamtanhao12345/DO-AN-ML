# Machine Learning Project - Malware classify
## Giới thiệu

Dự án này sử dụng các thư viện Python để xử lý dữ liệu, xây dựng, đánh giá và phân loại mã độc bằng các phương pháp học máy như Decision Tree, Random Forest và KNN. Mục tiêu của dự án là xây dựng các mô hình có khả năng phát hiện mã độc dựa trên các đặc trưng của mã nguồn.

Source code tham khảo từ nguồn:
- https://github.com/urwithajit9/ClaMP

Dữ liệu thô được thu thập từ các nguồn:
- Nhóm tự collect từ CNET (https://download.cnet.com)
- Virus Share
- [Benign-NET](https://github.com/bormaa/Benign-NET) được sử dụng trong bài báo "Hassan, M., Eid, M., Elnems, H., Ahmed, E., Mesak, E., Branco, P. "Detecting Malicious .NET Files Using CLR Header Features and Machine Learning" 36th Canadian Conference on Artificial Intelligence, Canadian AI 2023, Montreal, QC, Canada, June 5–9, 2023."
- [Malware Detection PE-Based Analysis Using Deep Learning Algorithm Dataset](https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642?file=12149696)

Các cách thiết lập môi trường, cấu trúc thư mục, sẽ được trình bày bên dưới:

## I. Cài đặt môi trường
```bash
Ngôn ngữ: Python 3.8.10
OS: Ubuntu 20.04
RAM: 8GB
CPU: 6 Core
Code Manager: Jupiter notebook
```

Để bắt đầu, chúng ta cần cài đặt môi trường Python và các thư viện cần thiết. Dưới đây là các bước để cài đặt môi trường và các thư viện yêu cầu:

### Bước 1: Clone dự án từ GitHub
```bash
git clone https://github.com/lamtanhao12345/DO-AN-ML
cd DO-AN-ML
```
### Bước 2: Tạo môi trường ảo và kích hoạt
Cài đặt Anaconda
```bash
curl https://repo.anaconda.com/archive/Anaconda3-2020.02-Linux-x86_64.sh --output anaconda.sh
bash anaconda.sh
```
Nếu sử dụng bashcli
```bash
source ~/.bashrc
```
Nếu sử dụng zshcli
```bash
source ~/.zshrc
```
Tạo môi trường ảo
```bash
conda create --name py3108 python=3.10.8
```
Kích hoạt môi trường ảo
```bash
conda activate py3108
```
### Bước 3: Cài đặt các thư viện yêu cầu
Cài đặt các thư viện cần thiết thông qua `pip`:
```bash
pip install -r src/requirements.txt
```
---
## Cấu trúc thư mục
```bash
Do-AN-ML/
│
├── data/                 # Dữ liệu thô và dữ liệu đã xử lý
├── notebooks/            # Các notebook phân tích và thử nghiệm
├── src/                  # Mã nguồn chính (xử lý dữ liệu, tạo đặc trưng, huấn luyện mô hình)
├── models/               # Mô hình học máy đã huấn luyện
├── reports/              # Báo cáo, đồ thị, kết quả
└── requirements.txt      # Các thư viện cần thiết
```
## **Thư viện sử dụng**
### **1. Xử lý tệp và dữ liệu**
- **`pickle`**:
  - Lưu trữ và tải dữ liệu hoặc mô hình dưới dạng nhị phân.
  - Dùng trong việc lưu và khôi phục trạng thái của các đối tượng Python.

- **`pandas`**:
  - Xử lý dữ liệu dạng bảng (DataFrame).
  - Được sử dụng để thao tác dữ liệu, phân tích, và xử lý dữ liệu lớn.

- **`math`**:
  - Cung cấp các hàm toán học cơ bản như căn bậc hai, lũy thừa, hàm lượng giác.

- **`numpy`**:
  - Xử lý dữ liệu số, hỗ trợ các thao tác trên mảng (array) một cách hiệu quả.
  - Thường được sử dụng để tính toán ma trận, vector trong học máy.

---

### **2. Phân tích file PE và rule matching**
- **`pefile`**:
  - Phân tích và thao tác trên các tệp PE (Portable Executable).
  - Hữu ích trong các ứng dụng bảo mật và phân tích mã độc.

- **`yara`**:
  - Công cụ so khớp mẫu (pattern matching) cho các chuỗi và tệp dữ liệu.
  - Thường được dùng trong phát hiện mã độc.

---

### **3. Học máy (Machine Learning)**
- **`scikit-learn`**:
  - Một thư viện phổ biến để xây dựng và đánh giá các mô hình học máy.
  - Các module sử dụng:
    - **`train_test_split`**: Chia dữ liệu thành tập huấn luyện và kiểm tra.
    - **`metrics`**:
      - `accuracy_score`, `precision_score`, `recall_score`, `f1_score`: Đánh giá độ chính xác, độ nhạy, và F1.
      - `PrecisionRecallDisplay`, `RocCurveDisplay`, `ConfusionMatrixDisplay`: Hiển thị các đồ thị đánh giá mô hình.
      - `classification_report`: Báo cáo chi tiết các chỉ số của mô hình.
    - **`ensemble.RandomForestClassifier`**:
      - Thuật toán học máy dựa trên các cây quyết định (Decision Trees).
    - **`neighbors.KNeighborsClassifier`**:
      - Thuật toán học máy dựa trên phương pháp láng giềng gần nhất.
    - **`tree.DecisionTreeClassifier`**:
      - Thuật toán học máy dựa trên cây quyết định.

---

## II. Xử lý dữ liệu
### Trích xuất đặc trưng bao gồm 61 đặc trưng, không tính nhãn (label):
#### 1. Đặc Trưng Từ DOS Header
DOS Header chứa các trường kế thừa từ định dạng tệp thực thi MS-DOS. Các đặc trưng được trích xuất bao gồm:
- **e_magic**: Chữ ký nhận dạng tệp là tệp thực thi DOS.
- **e_cblp, e_cp, e_crlc, e_cparhdr**: Các kích thước và offset khác nhau liên quan đến chương trình.
- **e_minalloc, e_maxalloc**: Bộ nhớ tối thiểu và tối đa yêu cầu bởi chương trình.
- **e_ss, e_sp, e_csum, e_ip, e_cs**: Các offset liên quan đến bộ nhớ và thực thi.
- **e_lfarlc**: Offset tệp đến bảng relocation.
- **e_ovno**: Số overlay.
- **e_oemid, e_oeminfo**: Thông tin đặc thù OEM.
- **e_lfanew**: Offset đến PE header.

#### 2. Đặc Trưng Từ File Header
File Header chứa thông tin về kiến trúc và các đặc tính cơ bản của tệp:
- **Machine**: Kiến trúc mục tiêu (ví dụ: x86, x64).
- **NumberOfSections**: Số lượng sections trong tệp.
- **TimeDateStamp**: Dấu thời gian biên dịch.
- **PointerToSymbolTable**: Con trỏ tệp đến bảng ký hiệu COFF.
- **NumberOfSymbols**: Số lượng ký hiệu trong bảng ký hiệu.
- **SizeOfOptionalHeader**: Kích thước của optional header.
- **Characteristics**: Các cờ xác định đặc tính của tệp.

#### 3. Đặc Trưng Từ Optional Header
Optional Header cung cấp thêm thông tin về bố cục và thực thi của tệp:
- **Magic**: Xác định loại tệp PE (ví dụ: PE32, PE32+).
- **MajorLinkerVersion, MinorLinkerVersion**: Phiên bản linker.
- **SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData**: Kích thước của các đoạn dữ liệu khác nhau.
- **AddressOfEntryPoint**: Điểm vào của tệp thực thi.
- **BaseOfCode, BaseOfData**: Địa chỉ cơ sở của đoạn mã và đoạn dữ liệu.
- **ImageBase**: Địa chỉ tải ưa thích của image.
- **SectionAlignment, FileAlignment**: Các quy định căn chỉnh.
- **MajorOperatingSystemVersion, MinorOperatingSystemVersion**: Phiên bản hệ điều hành mục tiêu.
- **MajorImageVersion, MinorImageVersion**: Phiên bản của tệp.
- **MajorSubsystemVersion, MinorSubsystemVersion**: Phiên bản subsystem.
- **SizeOfImage, SizeOfHeaders**: Tổng kích thước của image và các header.
- **CheckSum**: Tổng kiểm tra của tệp.
- **Subsystem**: Subsystem cần thiết để chạy image.
- **DllCharacteristics**: Đặc điểm dành riêng cho DLL.
- **SizeOfStackReserve, SizeOfStackCommit**: Kích thước bộ nhớ stack.
- **SizeOfHeapReserve, SizeOfHeapCommit**: Kích thước bộ nhớ heap.
- **LoaderFlags**: Dành riêng cho sử dụng trong tương lai.
- **NumberOfRvaAndSizes**: Số lượng entry directory trong PE header.

#### 4. Đặc Trưng Từ Section
Các đặc trưng này mô tả các section trong tệp PE:
- **SuspiciousSections, NonSuspiciousSections**: Số lượng section đáng ngờ và section lành tính dựa trên tên của chúng.

#### 5. Đặc Trưng Phát Hiện Packer
Các đặc trưng này cho biết sự hiện diện của các packer hoặc công cụ nén:
- **PackerDetected**: Cờ nhị phân chỉ định liệu có phát hiện packer hay không.
- **PackerType**: Loại packer được phát hiện (nếu có).

#### 6. Đặc Trưng Entropy và Kích Thước Tệp
Các đặc trưng này phân tích entropy (độ ngẫu nhiên) và kích thước của tệp và các section:
- **TextEntropy, DataEntropy**: Giá trị entropy của các section `.text` và `.data`.
- **FileSize**: Tổng kích thước của tệp tính theo byte.
- **FileEntropy**: Entropy tổng thể của tệp.
Ở đây nhóm em sử dụng công thức Shannon entropy. Cụ thể, công thức là:
![Shanon Entropy](reports/figures/Shanon%20Entropy.png)
```python
# Đếm tần suất xuất hiện của mỗi byte:
freq_list = [0] * 256
for byte in byte_arr:
    freq_list[byte] += 1

#Tính xác suất xuất hiện cho từng giá trị byte và áp dụng công thức:
entropy = -sum((freq / file_size) * math.log(freq / file_size, 2)
               for freq in freq_list if freq > 0)
```
#### 7. Nhãn (Label)
- **Label**: Nhãn được gán thủ công xác định phân loại của tệp (ví dụ: lành tính hay độc hại).


## III. Chạy code
### 1. Huấn luyện và Đánh giá Mô hình

Các mô hình được huấn luyện và đánh giá trong thư mục `notebooks/experiments`.

Ta có thể mở các notebook này để kiểm tra quá trình huấn luyện, đánh giá mô hình và điều chỉnh các tham số như `max_depth`, `n_estimators`, và `k` cho KNN.

```bash
cd src
python features/extract.py
```
Sau khi thực hiện đoạn code trên, ta sẽ thu được file `dataset.csv` trong thư mục dataset.

Tiếp theo thực hiện huấn luyện mô hình và export kết quả huấn luyện mô hình mô hình bằng cách:
```bash
cd src
python evaluation/RandomForest.py
python evaluation/DecisionTree.py
python evaluation/K-nearestNeighbors.py
```
### 2. Load model và thực hiện predict một số file khác không nằm trong tập huấn luyện
```bash
cd src
python evaluation/Predict.py ./tests
```