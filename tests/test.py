from src.models import DecisionTreeModel, RandomForestModel, KNNModel

# Load mô hình đã huấn luyện
decision_tree_model = DecisionTreeModel.load('models/decision_tree_model.pkl')
random_forest_model = RandomForestModel.load('models/random_forest_model.pkl')
knn_model = KNNModel.load('models/K_Nearest_Neighbors_model.pkl')

# Load data
load_data = ''

# Dự đoán
predictions = decision_tree_model.predict(data)
probabilities = decision_tree_model.predict_proba(data)
predicted_class = prediction[0]
confidence = probabilities[0][predicted_class] * 100

if prediction[0] == 1:
  result = f"[+] Prediction by Decision Tree is malware ({confidence:.2f}%) !!!\n"
else:
  result = f"[+] Prediction by Decision Tree is benign ({confidence:.2f}%)!!!\n"
