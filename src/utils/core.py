import hashlib
import os
import csv
import concurrent
import pefile
import yara
import logging
import numpy as np
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor


# Logging configuration
logging.basicConfig(
    filename='process_log.txt', level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Feature extraction functions
def extract_dos_header(pe):
    try:
        dos_header = pe.DOS_HEADER
        return [
            dos_header.e_magic,
            dos_header.e_cblp,
            dos_header.e_cp,
            dos_header.e_crlc,
            dos_header.e_cparhdr,
            dos_header.e_minalloc,
            dos_header.e_maxalloc,
            dos_header.e_ss,
            dos_header.e_sp,
            dos_header.e_csum,
            dos_header.e_ip,
            dos_header.e_cs,
            dos_header.e_lfarlc,
            dos_header.e_ovno,
            dos_header.e_oemid,
            dos_header.e_oeminfo,
            dos_header.e_lfanew
        ]
    except Exception:
        return [0] * 17

def extract_file_header(pe):
    try:
        file_header = pe.FILE_HEADER
        return [
            file_header.Machine,
            file_header.NumberOfSections,
            file_header.TimeDateStamp,
            file_header.PointerToSymbolTable,
            file_header.NumberOfSymbols,
            file_header.SizeOfOptionalHeader,
            file_header.Characteristics
        ]
    except Exception:
        return [0] * 7

def extract_optional_header(pe):
    try:
        optional_header = pe.OPTIONAL_HEADER
        return [
            optional_header.Magic,
            optional_header.MajorLinkerVersion,
            optional_header.MinorLinkerVersion,
            optional_header.SizeOfCode,
            optional_header.SizeOfInitializedData,
            optional_header.SizeOfUninitializedData,
            optional_header.AddressOfEntryPoint,
            optional_header.BaseOfCode,
            optional_header.BaseOfData,
            optional_header.ImageBase,
            optional_header.SectionAlignment,
            optional_header.FileAlignment,
            optional_header.MajorOperatingSystemVersion,
            optional_header.MinorOperatingSystemVersion,
            optional_header.SizeOfImage,
            optional_header.SizeOfHeaders,
            optional_header.CheckSum,
            optional_header.Subsystem,
            optional_header.DllCharacteristics,
            optional_header.SizeOfStackReserve,
            optional_header.SizeOfStackCommit,
            optional_header.SizeOfHeapReserve,
            optional_header.SizeOfHeapCommit,
            optional_header.LoaderFlags,
            optional_header.NumberOfRvaAndSizes
        ]
    except Exception:
        return [0] * 25

def get_count_suspicious_sections(pe):
    try:
        benign_sections = {b'.text', b'.data', b'.rdata', b'.idata', b'.edata', b'.rsrc', b'.bss', b'.crt', b'.tls'}
        section_names = [section.Name.strip() for section in pe.sections]
        non_suspicious = len(set(section_names).intersection(benign_sections))
        suspicious = len(section_names) - non_suspicious
        return [suspicious, non_suspicious]
    except Exception:
        return [0, 0]

def check_packer(filepath, rules):
    try:
        matches = rules.match(filepath)
        if matches:
            return [1, matches[0].rule]
        return [0, "NoPacker"]
    except Exception:
        return [0, "Error"]

def get_text_data_entropy(pe):
    try:
        text_entropy, data_entropy = 0.0, 0.0
        for section in pe.sections:
            if section.Name.startswith(b".text"):
                text_entropy = section.get_entropy()
            elif section.Name.startswith(b".data"):
                data_entropy = section.get_entropy()
        return [text_entropy, data_entropy]
    except Exception:
        return [0.0, 0.0]

def get_file_bytes_size(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        return data, len(data)
    except Exception:
        return b"", 0

def calculate_file_entropy(byte_arr, file_size):
    if file_size == 0:
        return 0.0
    _, counts = np.unique(byte_arr, return_counts=True)
    probabilities = counts / file_size
    return -np.sum(probabilities * np.log2(probabilities))

def extract_file_entropy(filepath):
    byte_arr, file_size = get_file_bytes_size(filepath)
    entropy = calculate_file_entropy(byte_arr, file_size)
    return [file_size, entropy]

def extract_import_export_features(pe):
    try:
        import_count = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        return [import_count, export_count]
    except Exception:
        return [0, 0]

def extract_features(pe, filepath, rules):
    features = []
    features.extend(extract_dos_header(pe))
    features.extend(extract_file_header(pe))
    features.extend(extract_optional_header(pe))
    features.extend(get_count_suspicious_sections(pe))
    features.extend(check_packer(filepath, rules))
    features.extend(get_text_data_entropy(pe))
    features.extend(extract_file_entropy(filepath))
    features.extend(extract_import_export_features(pe))
    return features

# CSV utility functions
def write_csv_header(output_path, header):
    if not os.path.exists(output_path):
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)

def write_csv_row(output_path, row):
    with open(output_path, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)

def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()

# PE file processing
def process_pe_file(filepath, rules, output_path, label):
    try:
        pe = pefile.PE(filepath)
        features = extract_features(pe, filepath, rules)
        features.append(md5sum(filename=filepath))
        features.append(label)
        write_csv_row(output_path, features)
        logging.info(f"Successfully processed: {filepath}")
    except pefile.PEFormatError as e:
        logging.warning(f"Invalid PE format: {filepath} - {e}")
    except Exception as e:
        logging.error(f"Failed to process {filepath}: {e}")

# Dataset creation with multi-threading
def process_files_concurrently(source_dir, output_path, yara_rules_path, label, max_workers=4):
    rules = yara.compile(yara_rules_path)
    header = (
        ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"] +
        ["Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"] +
        ["Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes"] +
        ["SuspiciousSections", "NonSuspiciousSections", "PackerDetected", "PackerType", "TextEntropy", "DataEntropy", "FileSize", "FileEntropy", "ImportCount", "ExportCount", "MD5", "Label"]
    )
    write_csv_header(output_path, header)

    files = [os.path.join(source_dir, f) for f in os.listdir(source_dir)]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_pe_file, filepath, rules, output_path, label) for filepath in files]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error during concurrent processing: {e}")
