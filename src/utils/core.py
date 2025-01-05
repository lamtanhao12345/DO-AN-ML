import os
import csv
import pefile
import yara
import math
from typing import List, Tuple

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
            optional_header.MajorImageVersion,
            optional_header.MinorImageVersion,
            optional_header.MajorSubsystemVersion,
            optional_header.MinorSubsystemVersion,
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
        return [0] * 29

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
    try:
        if file_size == 0:
            return 0.0
        freq_list = [0] * 256
        for byte in byte_arr:
            freq_list[byte] += 1
        entropy = -sum((freq / file_size) * math.log(freq / file_size, 2)
                       for freq in freq_list if freq > 0)
        return entropy
    except Exception:
        return 0.0

def extract_file_entropy(filepath):
    byte_arr, file_size = get_file_bytes_size(filepath)
    entropy = calculate_file_entropy(byte_arr, file_size)
    return [file_size, entropy]

def extract_features(pe, filepath, rules):
    features = []
    features.extend(extract_dos_header(pe))
    features.extend(extract_file_header(pe))
    features.extend(extract_optional_header(pe))
    features.extend(get_count_suspicious_sections(pe))
    features.extend(check_packer(filepath, rules))
    features.extend(get_text_data_entropy(pe))
    features.extend(extract_file_entropy(filepath))
    return features

def write_csv_header(output_path, header):
    if not os.path.exists(output_path):
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)

def write_csv_row(output_path, row):
    with open(output_path, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)

def process_pe_file(filepath, rules, output_path, label):
    try:
        pe = pefile.PE(filepath)
        features = extract_features(pe, filepath, rules)
        features.append(label)
        print(len(features))
        write_csv_row(output_path, features)
        print(f"Successfully processed {filepath}")
    except Exception as e:
        print(f"Failed to process {filepath}: {e}")

def create_dataset(source_dir, output_path, yara_rules_path, label):
    rules = yara.compile(yara_rules_path)
    header = (
        ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"] +
        ["Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"] +
        ["Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes"] +
        ["SuspiciousSections", "NonSuspiciousSections", "PackerDetected", "PackerType", "TextEntropy", "DataEntropy", "FileSize", "FileEntropy", "Label"]
    )
    write_csv_header(output_path, header)

    for filename in os.listdir(source_dir):
        filepath = os.path.join(source_dir, filename)
        process_pe_file(filepath, rules, output_path, label)