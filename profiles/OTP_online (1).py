from pyotp import HOTP, random_base32
from datetime import datetime
from random import choice
from string import digits
from json import dump, load
from os import path

def random_digit():
    random_code =  ''.join(choice(digits) for i in range(10))
    return int(random_code)

def read_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    return data

def read_json_file(path):
    with open(path) as f:
        data = load(f)
    return data

def write_json_file(path, data):
    with open(path, 'w') as f:
        dump(data, f, indent = 4)

def generate_json_file(path, object, dict):
    data = {
        object: []
    }
    data[object].append(dict)
    write_json_file(path, data)

def append_json_file(path, object, dict, session_id):
    data = read_json_file(path)
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
    write_json_file(path, data)

# def append_json_file(path, object, dict):
#     data = read_json_file(path)
#     temp = data[object]
#     # appending data to object
#     temp.append(dict)
#     write_json_file(path, data)

def OTP_generator():
    # Lay sessionID cua user
    session_id = 'abacavasdf'
    base32secret = random_base32()
    hotp = HOTP(base32secret)
    counter = random_digit()
    OTP_value = hotp.at(counter)
    time_create = datetime.now().strftime('%Y%m%d%H%M%S%f')
    # Tao data cho file json
    dict = {
        session_id: counter,
        'base32secret': base32secret,
        'time_create': time_create
    }
    # Neu file ton tai va khac rong
    if not path.isfile('./OTP.json') or read_file('./OTP.json') == b'':
        generate_json_file('./OTP.json', 'OTP', dict)
    else:
        append_json_file('./OTP.json', 'OTP', dict, session_id)

    print(OTP_value)
    return OTP_value

def OTP_verification(OTP_value):
    # Lay sessionID cua user
    session_id = 'abacavasdf'
    data = None
    counter, OTP_check, time_create = None, None, None
    # Neu file ton tai va khac rong
    if not path.isfile('./OTP.json') or read_file('./OTP.json') == b'':
        print('OTP expires!!!')
    else:
        data = read_json_file('./OTP.json')

    for i in reversed(range(len(data["OTP"]))):
        dict = data["OTP"][i]
        if session_id in dict:
            counter = dict[session_id]
            base32secret = dict['base32secret']
            time_create = dict['time_create']
            break

    time_verify = datetime.now().strftime('%Y%m%d%H%M%S%f')
    #2020 10 28 02 30 08 743182
    #2020 10 28 02 35 08 743183
    if time_create is not None and int(time_verify) - int(time_create) <= 500000000:
        hotp = HOTP(base32secret)
        if hotp.verify(OTP_value, counter):
            print('Correct')
        else:
            print("OTP is wrong!!")
    else:
        print("OTP expires!!!")

otp = OTP_generator()
OTP_verification(otp)