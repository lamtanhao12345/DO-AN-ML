import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, accuracy_score


data_path = '../dataset/dataset.csv'
data = pd.read_csv(data_path)

# remove duplicate
data = data.drop_duplicates(subset='MD5', keep='first')

# drop column not use
data = data.drop(columns='MD5',axis=1)
data = data.drop(columns='PackerType',axis=1)

print(data.groupby(data['Label']).size())


# Xem thông tin về dữ liệu
print(data.head())
print(data.info())

# Tách dữ liệu thành đầu vào (X) và nhãn (y)
x = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Chia dữ liệu thành tập train và test (75% train, 25% test)
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=y)


# Sử dụng GridSearchCV để tìm giá trị tốt nhất
from sklearn.model_selection import GridSearchCV

param_grid = {'n_neighbors': [3, 5, 7, 10, 12, 15, 18]}
grid = GridSearchCV(KNeighborsClassifier(), param_grid, cv=5)
grid.fit(X_train, y_train)
print("Best parameters:", grid.best_params_)

# Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Khởi tạo mô hình KNN
k = grid.best_params_['n_neighbors']
knn = KNeighborsClassifier(n_neighbors=k)

# Train mô hình
knn.fit(X_train, y_train)

# Dự đoán trên tập test
y_pred = knn.predict(X_test)

# Đánh giá mô hình
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nBáo cáo về kết quả phân loại:\n", classification_report(y_test, y_pred))


import joblib
# Lưu mô hình đã huấn luyện vào file .pkl
model_filename = 'models/K-nearestNeighbors.pkl'
joblib.dump(knn, model_filename)
print(f'Model saved as {model_filename}')
