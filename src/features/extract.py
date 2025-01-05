from ..utils.core import *

PATH_BENIGN = './data/raw/benign/'
PATH_MALWARE = './data/raw/malware/'

create_dataset(source_dir=PATH_BENIGN, output_path="benign.csv", yara_rules_path="peid.yar", label="0")
create_dataset(source_dir=PATH_MALWARE, output_path="benign.csv", yara_rules_path="peid.yar", label="1")