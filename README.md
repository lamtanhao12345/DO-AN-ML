# Machine Learning Project - Malware classify

## Giới thiệu
Dự án này sử dụng các thư viện Python để xử lý dữ liệu, xây dựng, đánh giá và phân loại mã độc bằng các phương pháp học máy như Decision Tree, Random Forest và KNN. Mục tiêu của dự án là xây dựng các mô hình có khả năng phát hiện mã độc dựa trên các đặc trưng của mã nguồn. Các cách thiết lập môi trường, cấu trúc thư mục, sẽ được trình bày bên dưới:

---

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

## **Cách cài đặt**
```bash
pip install -r requirements.txt
