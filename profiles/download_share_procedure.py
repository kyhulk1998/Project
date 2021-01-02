from string import ascii_letters
from hashlib import sha256, blake2b, md5, sha512
from pyotp import HOTP
from base64 import b32encode
from PyPDF2 import PdfFileWriter, PdfFileReader
from json import dump, load
from os import path


def read_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    return data


def read_json_file(file_path):
    with open(file_path) as f:
        data = load(f)
    return data


def write_json_file(file_path, data):
    with open(file_path, 'w') as f:
        dump(data, f, indent=4)


def generate_json_file(file_path, object, dict):
    data = {
        object: []
    }
    data[object].append(dict)
    write_json_file(file_path, data)


def append_OTP_json_file(file_path, object, dict, session_id):
    data = read_json_file(file_path)
    list_dict = data[object]
    for i in reversed(range(len(list_dict))):
        temp = list_dict[i]
        check = 0
        if session_id in temp:
            check = 1
            temp[session_id] = dict[session_id]
            temp['base32secret'] = dict['base32secret']
            temp['time_create'] = dict['time_create']
            break
    if check == 0:
        list_dict.append(dict)
    write_json_file(file_path, data)


def file_is_not_existed(file_path):
    if not path.isfile(file_path) or read_file(file_path) == b'':
        return True
    else:
        return False


# bat dau
def create_license_id(last_license_id):
    new_license_id = ''
    # Neu database chua co licenseID nao
    if last_license_id is None:
        new_license_id = 'abcdef'
    else:
        list_string = ascii_letters
        new_index = []
        for i in range(6):
            new_index.append(list_string.index(last_license_id[i]))
        # print(new_index)
        if new_index[5] >= 51:
            new_index[5] = 0
            if new_index[4] >= 51:
                new_index[4] = 0
                if new_index[3] >= 51:
                    new_index[3] = 0
                    if new_index[2] >= 51:
                        new_index[2] = 0
                        if new_index[1] >= 51:
                            new_index[1] = 0
                            if new_index[0] >= 51:
                                return 'Exhaust License ID!'
                            else:
                                new_index[0] += 1
                        else:
                            new_index[1] += 1
                    else:
                        new_index[2] += 1
                else:
                    new_index[3] += 1
            else:
                new_index[4] += 1
        else:
            new_index[5] += 1
        # print(new_index)
        for i in new_index:
            new_license_id += list_string[i]
        print(new_license_id)
    return new_license_id


# Create combine hash
def hash_generator(var_1, var_2, var_3):
    var_1_hash = sha256(var_1.encode('ascii')).hexdigest()
    var_2_hash = blake2b(var_2.encode('ascii')).hexdigest()
    var_3_hash = md5(var_3.encode('ascii')).hexdigest()
    return sha512((var_1_hash + var_2_hash + var_3_hash).encode('ascii')).hexdigest()


# Create encryption key - server & desktop app
def key_synchronous_generator(license_id, editable, printable, username, phone, owner):
    hash_value = hash_generator(str(editable + printable), username + phone, owner)
    return sha256((hash_value + license_id + ' ').encode('ascii')).hexdigest()
# key_synchronous_generator("abcdek","0","0","kynguyen5698@gmail.com","0333721887","hung@gmail.com")

# Create OTP - server & desktop app
def OTP_synchronous_generator(license_id, downloader, username, phone, expDate, random_code):
    # Static random (6 digits) lay tu database
    static_random = 'asfb86'
    expDate = str(expDate)
    hash_value = hash_generator(license_id + downloader, username + phone, expDate + static_random)
    hash_value_base32 = b32encode(hash_value.encode('ascii'))
    hotp = HOTP(hash_value_base32)
    OTP_value = hotp.at(int(random_code))
    return OTP_value

def synchronous_encryption(file_path, synchronous_key):
    print(file_path,synchronous_key)
    pdfWriter = PdfFileWriter()
    pdfReader = PdfFileReader(file_path)
    for page_num in range(pdfReader.numPages):
        pdfWriter.addPage(pdfReader.getPage(page_num))
    pdfWriter.encrypt(synchronous_key)
    with open(file_path, 'wb') as doc:
        pdfWriter.write(doc)
        doc.close()


def compute_hash_file(file_path):
    if file_is_not_existed(file_path):
        raise Exception('File does not exist!!')
    data = read_file(file_path)
    return sha256(data).hexdigest()
