import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

data_path = '../dataset/dataset.csv'
data = pd.read_csv(data_path)
data = data.drop(columns='PackerType',axis=1)

# Xem thông tin về dữ liệu
# print(data.head())
# print(data.info())

# Tách dữ liệu thành đầu vào (X) và nhãn (y)
x = data.iloc[:, :-1]  # Giả sử cột cuối là nhãn
y = data.iloc[:, -1]


# Chia dữ liệu thành tập train và test (60% sử dụng để train, 40% sử dụng để test)
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.4, random_state=42, stratify=y)


# Khởi tạo mô hình Random Forest
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,  # Giới hạn độ sâu cây
    min_samples_split=10,  # Giới hạn số mẫu để tách
    random_state=42
)

# Train mô hình
rf.fit(X_train, y_train)

# Dự đoán trên tập test
y_pred = rf.predict(X_test)

# Đánh giá mô hình
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))


import joblib
# Lưu mô hình đã huấn luyện vào file .pkl
model_filename = 'models/random_forest_model.pkl'
joblib.dump(rf, model_filename)
print(f'Model saved as {model_filename}')