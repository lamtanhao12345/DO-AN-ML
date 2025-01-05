import os
import csv
import math
import pefile
import yara

# Utility functions

def file_creation_year(seconds):
    return int((1970 + (int(seconds) / 86400) / 365) in range(1980, 2016))

def char_boolean_set(pe_file_header, flags):
    return [int(getattr(pe_file_header, flag)) for flag in flags]

def optional_header_image_base(image_base):
    if image_base % (64 * 1024) == 0 and image_base in [268435456, 65536, 4194304]:
        return 1
    return 0

def optional_header_alignment_check(section_alignment, file_alignment):
    return int(section_alignment >= file_alignment)

def optional_header_file_alignment_check(section_alignment, file_alignment):
    if section_alignment >= 512:
        return 1 if file_alignment % 2 == 0 and file_alignment in range(512, 65537) else 0
    return int(file_alignment == section_alignment)

def optional_header_size_of_image_check(size_of_image, section_alignment):
    return int(size_of_image % section_alignment == 0)

def optional_header_size_of_headers_check(size_of_headers, file_alignment):
    return int(size_of_headers % file_alignment == 0)

def extract_dos_header(pe):
    try:
        return [
            pe.DOS_HEADER.e_cblp,
            pe.DOS_HEADER.e_cp,
            pe.DOS_HEADER.e_cparhdr,
            pe.DOS_HEADER.e_maxalloc,
            pe.DOS_HEADER.e_sp,
            pe.DOS_HEADER.e_lfanew
        ]
    except Exception:
        return [0] * 6

def extract_file_header(pe):
    try:
        return [
            pe.FILE_HEADER.NumberOfSections,
            file_creation_year(pe.FILE_HEADER.TimeDateStamp)
        ]
    except Exception:
        return [0] * 3

def extract_optional_header(pe):
    try:
        return [
            pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.MinorLinkerVersion,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.BaseOfCode,
            pe.OPTIONAL_HEADER.BaseOfData,
            optional_header_image_base(pe.OPTIONAL_HEADER.ImageBase),
            optional_header_alignment_check(pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment),
            optional_header_file_alignment_check(pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment),
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MajorImageVersion,
            pe.OPTIONAL_HEADER.MinorImageVersion,
            pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            optional_header_size_of_image_check(pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.SectionAlignment),
            optional_header_size_of_headers_check(pe.OPTIONAL_HEADER.SizeOfHeaders, pe.OPTIONAL_HEADER.FileAlignment),
            pe.OPTIONAL_HEADER.CheckSum,
            pe.OPTIONAL_HEADER.Subsystem
        ]
    except Exception:
        return [0] * 21

def check_packer(filepath, rules):
    matches = rules.match(filepath)
    if matches:
        return [1, matches[0]]
    return [0, "NoPacker"]

def calculate_entropy(section):
    return section.get_entropy()

def get_file_bytes_size(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    return data, len(data)

def calculate_byte_frequency(byte_arr, file_size):
    return [float(byte_arr.count(b) / file_size) for b in range(256)]

def calculate_file_entropy(filepath):
    byte_arr, file_size = get_file_bytes_size(filepath)
    freq_list = calculate_byte_frequency(byte_arr, file_size)
    return file_size, sum(-freq * math.log(freq, 2) for freq in freq_list if freq > 0)

# Class for handling PE features extraction and dataset creation
class PEFeatures:
    IMAGE_DOS_HEADER = [
        "e_cblp", "e_cp", "e_cparhdr", "e_maxalloc", "e_sp", "e_lfanew"
    ]

    FILE_HEADER = [
        "NumberOfSections", "CreationYear"] + [f"FH_char{i}" for i in range(15)]

    OPTIONAL_HEADER1 = [
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment",
        "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
        "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem"
    ]

    OPTIONAL_HEADER_DLL_CHAR = [f"OH_DLLchar{i}" for i in range(11)]

    OPTIONAL_HEADER2 = [
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve",
        "SizeOfHeapCommit", "LoaderFlags"
    ]

    OPTIONAL_HEADER = OPTIONAL_HEADER1 + OPTIONAL_HEADER_DLL_CHAR + OPTIONAL_HEADER2
    DERIVED_HEADER = ["sus_sections", "non_sus_sections", "packer", "E_text", "E_data", "filesize", "E_file", "fileinfo"]

    def __init__(self, source, output, label):
        self.source = source
        self.output = output
        self.type = label
        self.rules = yara.compile('peid.yar')

    def write_csv_header(self):
        if os.path.exists(self.output): return
        filepath = self.output
        header = self.IMAGE_DOS_HEADER + self.FILE_HEADER + self.OPTIONAL_HEADER + self.DERIVED_HEADER
        header.append("class")
        with open(filepath, "a") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(header)

    def extract_all(self, filepath):
        data = []
        try:
            pe = pefile.PE(filepath)
            data += extract_dos_header(pe)
            data += extract_file_header(pe)
            data += extract_optional_header(pe)
            # Further processing...
        except Exception as e:
            print(f"Error extracting data from {filepath}: {e}")
            return None
        return data

    def write_csv_data(self, data):
        with open(self.output, "a") as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(data)

    def create_dataset(self):
        self.write_csv_header()
        for count, file in enumerate(os.listdir(self.source)):
            print(f"Extracting features from {count + 1} / {len(os.listdir(self.source))}")
            filepath = os.path.join(self.source, file)
            data = self.extract_all(filepath)
            if data:
                self.write_csv_data(data)
                print(f"Data extracted and written for {file}")
