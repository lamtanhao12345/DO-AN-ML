import sys
sys.path.append('.')

from utils.core import *

# 4966 files
PATH_BENIGN = './data/raw/benign/'
# 4756 files 
PATH_MALWARE = './data/raw/malware/'

process_files_concurrently(source_dir=PATH_BENIGN, output_path="benign.csv", yara_rules_path="peid.yar", label="0", max_workers=5)
process_files_concurrently(source_dir=PATH_MALWARE, output_path="malware.csv", yara_rules_path="peid.yar", label="1", max_workers=5)


#  Merge 2 file de tao ra dataset
import pandas as pd
file1_path = 'benign.csv'
file2_path = 'malware.csv'
df1 = pd.read_csv(file1_path)
df2 = pd.read_csv(file2_path)
df2 = df2.iloc[1:].reset_index(drop=True)
# Append df2 vào df1
merged_df = df1._append(df2, ignore_index=True)
output_path = '../dataset/dataset.csv'
merged_df.to_csv(output_path, index=False)
print(f'Merged file saved as {output_path}')