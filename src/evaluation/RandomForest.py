import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

data_path = '../dataset/dataset.csv'
data = pd.read_csv(data_path)

# remove duplicate
data = data.drop_duplicates(subset='MD5', keep='first')

# drop column not use
data = data.drop(columns='MD5',axis=1)
data = data.drop(columns='PackerType',axis=1)


# Tách dữ liệu thành đầu vào (X) và nhãn (y)
x = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Chuẩn hóa dữ liệu (nếu cần)
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x)

# Chia dữ liệu thành tập train và test (75% train, 25% test)
X_train, X_test, y_train, y_test = train_test_split(x_scaled, y, test_size=0.25, random_state=42, stratify=y)

# Khởi tạo mô hình Random Forest
rf = RandomForestClassifier(random_state=42)

# Tuning siêu tham số với GridSearchCV
param_grid = {
    'n_estimators': [100, 150, 200],
    'max_depth': [10, 20, 30],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'bootstrap': [True, False]
}

# Sử dụng GridSearchCV để tìm siêu tham số tốt nhất
grid_search = GridSearchCV(estimator=rf, param_grid=param_grid, cv=5, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

# In ra siêu tham số tối ưu
print("Best Parameters:", grid_search.best_params_)

# Dự đoán với mô hình tối ưu
best_rf = grid_search.best_estimator_
y_pred = best_rf.predict(X_test)

# Đánh giá mô hình
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Cross-validation đánh giá
cv_scores = cross_val_score(best_rf, x_scaled, y, cv=5)
print("\nCross-Validation Scores:", cv_scores)
print("Mean CV Score:", cv_scores.mean())
