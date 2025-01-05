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

## Cài đặt môi trường
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
Sử dụng `venv` để tạo môi trường ảo:
```bash
python3 -m venv venv
source venv/bin/activate
```
### Bước 3: Cài đặt các thư viện yêu cầu
Cài đặt các thư viện cần thiết thông qua `pip`:
```bash
pip install -r requirements.txt
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
## **Thư viện đã sử dụng**
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


## **Cách sử dụng các mô hình**
Huấn luyện và Đánh giá Mô hình
Các mô hình được huấn luyện và đánh giá trong thư mục `notebooks/experiments`. Bạn có thể mở các notebook này để kiểm tra quá trình huấn luyện, đánh giá mô hình và điều chỉnh các tham số như `max_depth`, `n_estimators`, và `k` cho KNN.
## **Dự đoán với mô hình đã huấn luyện**
Sau khi mô hình đã được huấn luyện, chúng ta có thể sử dụng mô hình để dự đoán trên dữ liệu mới:
```python
from src.models import DecisionTreeModel, RandomForestModel, KNNModel

# Load mô hình đã huấn luyện
decision_tree_model = DecisionTreeModel.load('models/decision_tree_model.pkl')
random_forest_model = RandomForestModel.load('models/random_forest_model.pkl')
knn_model = KNNModel.load('models/K_Nearest_Neighbors_model.pkl')

# Dự đoán
predictions = decision_tree_model.predict(new_data)
probabilities = decision_tree_model.predict_proba(data)
predicted_class = prediction[0]
confidence = probabilities[0][predicted_class] * 100

if prediction[0] == 1:
  result = f"[+] Prediction by Decision Tree is malware ({confidence:.2f}%) !!!\n"
else:
  result = f"[+] Prediction by Decision Tree is benign ({confidence:.2f}%)!!!\n"

```

