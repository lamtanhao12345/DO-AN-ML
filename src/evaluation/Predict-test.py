import sys
sys.path.append('.')

from utils.core import *

import os
import sys
import numpy as np
import joblib
import pefile
from sklearn.preprocessing import StandardScaler

# Hàm trích xuất các đặc trưng cơ bản từ file PE
def process_pe_file(filepath, yara_rules_path='peid.yar'):
    try:
        rules = yara.compile(yara_rules_path)
        pe = pefile.PE(filepath)
        features = extract_features(pe, filepath, rules)
        features.remove(features[-7]) # Xóa feature Packer_type
        # print(features[-7])
        return features
    except Exception as e:
        print(f"Failed to process {filepath}: {e}")

# Hàm để tải mô hình
def load_models():
    # Tải các mô hình đã huấn luyện từ các file .pkl
    decision_tree_model = joblib.load('../models/decision_tree_model.pkl')
    knn_model = joblib.load('../models/K-nearestNeighbors.pkl')
    random_forest_model = joblib.load('../models/random_forest_model.pkl')
    return decision_tree_model, knn_model, random_forest_model

# Hàm dự đoán cho một file PE
def predict_pe(pe_file, models):
    features = process_pe_file(pe_file)
    if features is None:
        return None
    
    features_array = np.array(features).reshape(1, -1)
    
    predictions = []
    for model in models:
        pred = model.predict(features_array)
        predictions.append(pred[0])
    
    return predictions

def main(folder_path):
    if not os.path.isdir(folder_path):
        print(f"Error: The folder {folder_path} does not exist.")
        return
    
    # Tải các mô hình và scaler
    decision_tree_model, knn_model, random_forest_model = load_models()
    models = [decision_tree_model, knn_model, random_forest_model]
    
    # Duyệt qua tất cả các file trong thư mục và thực hiện dự đoán
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        
        if os.path.isfile(file_path) and file_path.endswith('.exe'):
            predictions = predict_pe(file_path, models)
            
            print('-'*50)
            if predictions:
                print(f"Predictions for {filename}:")
                print(f"Decision Tree: {'Malware' if predictions[0] == 1 else 'Benign'}")
                print(f"KNN: {'Malware' if predictions[1] == 1 else 'Benign'}")
                print(f"Random Forest: {'Malware' if predictions[2] == 1 else 'Benign'}")
            else:
                print(f"Error processing file: {filename}")
                
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python Predict-test.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    main(folder_path)
