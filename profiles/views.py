import hashlib
import random
import os
from zipfile import ZipFile
import time
from django.contrib.auth import update_session_auth_hash
from cryptography.fernet import Fernet
from django.db.models import Count
from pyotp import HOTP, random_base32
from django.http import JsonResponse
from django.views.generic import FormView
from django.conf import settings
# from pyotp import HOTP
# from base64 import b32encode
from datetime import datetime, timezone
from random import choice
from string import digits
# from django import forms
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import LogoutView
# from django.core.mail import send_mail
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.views.generic import TemplateView
from googleapiclient.http import MediaFileUpload
from django.core.mail import EmailMultiAlternatives
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from django.contrib.auth.models import User
from .forms import RegistrationForm, PermisssionForm
from django.contrib.auth.forms import PasswordChangeForm
from .models import Drive, File, ShareFile, OTP, downloadFile, File_Analysis
from oauth2client import file, client, tools
from googleapiclient import discovery
from httplib2 import Http
from .download_share_procedure import *
from .SMSgateway import recevieSmsMessage, sendSmsMessage
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.http import FileResponse, Http404
from dateutil.parser import parse
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.storage import FileSystemStorage

gauth = GoogleAuth()
drive = GoogleDrive(gauth)
SCOPES = 'https://www.googleapis.com/auth/drive'
store = file.Storage('profiles/token2.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('client_secrets.json', SCOPES)
    creds = tools.run_flow(flow, store)
DRIVE = discovery.build('drive', 'v3', http=creds.authorize(Http()))
DRIVES = discovery.build('drive', 'v2', http=creds.authorize(Http()))


def login_request(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"Welcome back, {username}")
                return redirect('/profile/viewfile/')
        else:
            messages.error(request,
                           mark_safe(
                               "Invalid username or password! Please check again or  <a href='/register'>click here</a> to register"))
            return redirect('/')
    form = AuthenticationForm()
    return render(request=request,
                  template_name="baseIndex.html",
                  context={"form": form})


def userProfile(request):
    phone_number = request.user.first_name
    new_phone = phone_number.replace(phone_number[0:3], '0')
    context = {'user': request.user, 'new_phone': new_phone}
    return render(request, 'userProfile.html', context)


def register(request):
    form = RegistrationForm()
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            new_user = authenticate(username=form.cleaned_data['username'],
                                    password=form.cleaned_data['password1'],
                                    )
            login(request, new_user)
            return HttpResponseRedirect("/createfolder")

    return render(request, 'register.html', {'form': form})


def createFolder(request):
    if request.method == 'POST':
        current_user = request.user
        username = current_user.username
        folder = drive.CreateFile({'title': username, 'mimeType': 'application/vnd.google-apps.folder'})
        folder.Upload()
        messages.info(request, f"Welcome {username}. Please read our document carefully before enjoy!")
        Drive.objects.update_or_create(driveID=folder['id'], driveName=folder['title'], driveOwner_id=current_user.id)
        return HttpResponseRedirect("/profile")
    return render(request, 'createfolder.html')


def viewfilebyusername(request):
    current_user = request.user
    if current_user.is_superuser == True:
        size = 100
        list_file = DRIVE.files().list(
            pageSize=size, fields="nextPageToken, files(id, name, mimeType)").execute()
    else:
        try:
            a = Drive.objects.get(driveOwner_id=current_user.id)
            folderid = a.driveID
            query = f"parents = '{folderid}'"
            list_file = DRIVE.files().list(q=query).execute()
        except Drive.DoesNotExist:
            messages.warning(request,'Your account is login somewhere else')
            return HttpResponseRedirect('/')
    return render(request, 'profile.html', list_file)


def viewDetail(request):
    if request.method == "POST":
        current_id = request.POST['filedetail']
        name = request.POST['name']
        user_id = request.user.id
        a = ShareFile.objects.filter(file_id_id=current_id, owner_id=user_id)
        shareFileRecord = ShareFile.objects.filter(file_id_id=current_id, owner_id=user_id).values_list('shareFileID',
                                                                                                     flat=True)
        list_shareFileID = list(shareFileRecord)
        downloadFileRecord = downloadFile.objects.filter(sharefile_id__in=[item for item in list_shareFileID])
        filede = DRIVE.files().get(fileId=current_id, fields='size, createdTime').execute()
        dt = filede['createdTime']
        mod = parse(dt)

        context = {'size': filede['size'], 'createdTime': mod, 'data': a, 'download': downloadFileRecord, 'name': name}

    return render(request, 'filedetail.html', context)


def write_file(file_path, data):
    with open(file_path, "wb") as file:
        file.write(data)


def encrypt_file_stored_on_Cloud(filename):
    key = Fernet.generate_key()
    f = Fernet(key)
    plaintext_data = read_file(filename)
    # encrypt data
    encrypted_data = f.encrypt(plaintext_data)
    # write the encrypted file
    write_file(filename, encrypted_data)
    return key


def decrypt_file_stored_on_Cloud(file_id, filename):
    item = ShareFile.objects.get(shareFileID=file_id)
    key = File.objects.get(fileID=item.file_id_id).secretKey.encode('utf-8')
    f = Fernet(key)
    encrypted_data = read_file(filename)
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    write_file(filename, decrypted_data)


def decrypt_file_stored_on_Cloud2(file_id, filename):
    item = File.objects.get(fileID=file_id)
    key = item.secretKey.encode('utf-8')
    f = Fernet(key)
    encrypted_data = read_file(filename)
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    write_file(filename, decrypted_data)


def upinf(request):
    # basedir = r"D:\\"
    if request.method == "POST":
        current_user = request.user
        a = Drive.objects.get(driveOwner_id=current_user.id)
        fol_id = a.driveID
        filename = request.POST["fileupload"]
        key = encrypt_file_stored_on_Cloud(filename)
        try:
            file_metadata = {'name': filename, 'parents': [fol_id]}
            media = MediaFileUpload(filename, mimetype='application/pdf', resumable=True)
            DRIVE.files().create(body=file_metadata,
                                 media_body=media,
                                 fields='id').execute()
            query = f"parents = '{fol_id}'"
            list_file = DRIVE.files().list(q=query).execute()
            for file in list_file.get('files', []):
                File.objects.update_or_create(driveID_id=fol_id, secretKey=key.decode("utf-8"), fileID=file['id'],
                                              fileName=filename)
        except Exception as e:
            print(e)
        messages.success(request, 'Upload File Success')
        return HttpResponseRedirect('/profile/viewfile/')
    return render(request, 'profile.html', {})


def create(request):
    form = PermisssionForm()
    if request.method == "POST":
        fileid = request.POST['fileid']
        a = File.objects.get(fileID=fileid)
        create = a.fileID
        item = DRIVE.files().get(fileId=create).execute()
        con = {'id': item['id'], 'name': item['name'], 'form': form}
    return render(request, 'create.html', con)


def back(request):
    return render(request, 'profile.html', {})


def createLink(request):
    if request.method == "POST":
        current_user = request.user
        try:
            filid = request.POST['filid']
            filname = request.POST['filname']
            email = request.POST['shareEmails']
            editable = request.POST['editable']
            printable = request.POST['printable']
            downloadable = request.POST['downloadable']
            expDate = request.POST['expDate']
            id = User.objects.get(username=email)
            f = drive.CreateFile({'id': filid, 'title': filname})
            f.GetContentFile(filname, 'application/pdf')
            file_meta = {'name': filname, 'parents': ['1JuyWaMD46VcLXtGJyKMR8jQWHl1X_OSq']}
            media = MediaFileUpload(filname, mimetype='application/pdf', resumable=True)
            DRIVE.files().create(body=file_meta,
                                 media_body=media,
                                 fields='id').execute()
            query = f"parents = '{'1JuyWaMD46VcLXtGJyKMR8jQWHl1X_OSq'}'"
            filess = DRIVE.files().list(q=query).execute()
            for item in filess.get('files', []):
                linkshare = "localhost:8000/linkshare/" + item['id']
                ShareFile.objects.create(shareFileID=item['id'], file_id_id=filid, share_file_name=filname,
                                         shareEmails=email, owner_name=request.user.username,
                                         owner_id=current_user.id, link=linkshare, editable=editable,
                                         printable=printable,
                                         downloadable=downloadable, expDate=expDate)
                File_Analysis.objects.create(shareFileID_id=item['id'], UserID_id=id.id)
            # return HttpResponseRedirect("/linkshare")
        except Exception as e:
            print(e)
    return render(request, 'back&sendMail.html', {})


def sendMail(request):
    if request.method == "POST":
        a = ShareFile.objects.latest('date_create')
        subject, sender, to = 'LinkViewFile', settings.EMAIL_HOST_USER, a.shareEmails
        text_content = 'Hi, you have new sharing file'
        html_content = 'Hi, you have new sharing file.' \
                       '<a href="http://localhost:8000/check/' + a.shareFileID + '"> Click here </a> to view.'
        msg = EmailMultiAlternatives(subject, text_content, sender, [to])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        messages.success(request, "Share file successfully")
    return HttpResponseRedirect('/profile/viewfile/')


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            redirect('usrprofile')
        else:
            messages.error(request, 'Something wrong.Please check again')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_pwd.html', {
        'form': form
    })


def linkshare(request, file_id):
    con = {'id': file_id}
    return render(request, 'link.html', con)


def viewsharefile(request):
    if request.method == "POST":
        if request.method == "POST":
            share = request.POST['shareid']
            flag = ShareFile.objects.get(shareFileID=share)
            context = {'id': share, 'name': flag.share_file_name, 'flag': flag}
    return render(request, 'share/profileSharing.html', context)

def view_revoke(request):
    file_id = request.POST['file_id']
    fname = request.POST['name']
    user_id = request.user.id
    a = ShareFile.objects.filter(file_id_id=file_id, owner_id=user_id)
    shareFileRecord = ShareFile.objects.filter(file_id_id=file_id, owner_id=user_id).values_list('shareFileID',
                                                                                                 flat=True)
    list_shareFileID = list(shareFileRecord)
    downloadFileRecord = downloadFile.objects.filter(sharefile_id__in=[item for item in list_shareFileID])
    return render(request, 'view_revoke.html', {'data': a, 'data1': downloadFileRecord})


def revokeFile_Offline(request):
    if request.method == "POST":
        current_id = request.POST['filedel']
        fileid = downloadFile.objects.get(licenseID=current_id)
        fileid.delete()
        messages.success(request, "Revoke Successfully")
        return redirect('view')
    return render(request, 'view_revoke.html')


def revokeFile_Online(request):
    if request.method == "POST":
        current_sharefile_id = request.POST['filedel']
        #print(current_sharefile_id)
        fileid = ShareFile.objects.get(shareFileID=current_sharefile_id)
        DRIVES.parents().delete(fileId=current_sharefile_id, parentId='1JuyWaMD46VcLXtGJyKMR8jQWHl1X_OSq').execute()
        fileid.delete()
        messages.success(request, "Revoke Successfully")
        return redirect('view')
    return render(request, 'view_revoke.html')


def login_check(request, file_id):
    if request.method == 'POST':
        x = request.path.lstrip('/check/')
        y = x.rstrip('/')
        file_id = y
        try:
            a = ShareFile.objects.get(shareFileID=file_id)
            date_exp = a.expDate
            timenow = datetime.now(timezone.utc)
            form = AuthenticationForm(request=request, data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(username=username, password=password)
                if username == a.shareEmails:
                    if date_exp > timenow:
                        if not request.user.is_authenticated:
                            login(request, user)
                            return HttpResponseRedirect('/linkshare/' + a.shareFileID)
                        else:
                            messages.info(request,"Your account is login somewhere else")
                            return HttpResponseRedirect('/check/' + a.shareFileID)
                    else:
                        messages.error(request,
                                       'Your file is expired. Please contact ' + a.owner_name + ' for more information.')
                        render(request, 'logincheck.html')
                else:
                    messages.error(request, "Something wrong! You don't have enought permission to access this file!")
                    return render(request, 'logincheck.html')
            else:
                messages.error(request, 'Username or password is invalid. Please check again.')
        except ShareFile.DoesNotExist:
            messages.error(request, "Your file is revoke by file's owner. Please contact them for more information.")
            return render(request, 'logincheck.html')
    form = AuthenticationForm()
    return render(request=request,
                  template_name="logincheck.html",
                  context={"form": form})


# profilesharing
def sendMailOTP(request):
    if request.method == "POST":
        a = ShareFile.objects.latest('date_create')
        OTP_value = OTP_generator(request)
        id = request.POST['fileid']
        subject, sender, to = 'OTP Code', settings.EMAIL_HOST_USER, request.user.username
        text_content = 'OTP Value: ' + OTP_value
        # OTP.objects.update_or_create(otp_id = OTP_value, owner_id = b.id, email=a.shareEmails, file_id_id=fileid)
        msg = EmailMultiAlternatives(subject, text_content, sender, [to])
        msg.send()
        # con = {'file_id_id': fileid}
    return render(request, 'verifyOTP.html', {'id': id})


# resendOTP
def sendmailOTP(request):
    if request.method == "POST":
        a = ShareFile.objects.latest('date_create')
        OTP_value = OTP_generator(request)
        subject, sender, to = 'OTP Code', settings.EMAIL_HOST_USER, request.user.username
        text_content = 'OTP Value: ' + OTP_value
        # OTP.objects.update_or_create(otp_id = OTP_value, owner_id = b.id, email=a.shareEmails, file_id_id=fileid)
        msg = EmailMultiAlternatives(subject, text_content, sender, [to])
        msg.send()
        # con = {'file_id_id': fileid}
    return render(request, 'verifyOTP.html', {})


def viewOnline_Owner(request):
    if request.method == "POST":
        current_user = request.POST['fileview']
        name = request.POST['name']
        f = drive.CreateFile({'id': current_user, 'title': name})
        f.GetContentFile(name, 'application/pdf')
        decrypt_file_stored_on_Cloud2(current_user, name)
        os.replace("D:/WebServer/Project_new/Project/" + name,
                   "D:/WebServer/Project_new/Project/static/" + name)
    return render(request, 'renderToViewOnline.html', {'name': name})


def viewOnline(request):
    if request.method == "POST":
        otp_check = request.POST['otps']
        check = OTP_verification(request, otp_check)
        id = request.POST['fileID']
        if check == 1:
            a = ShareFile.objects.get(shareFileID=id)
            if a.editable == 0 and a.printable == 0:
                return redirect('http://localhost:4200/')
            elif a.editable == 0 and a.printable == 1:
                return redirect('http://localhost:4400/')
            elif a.editable == 1 and a.printable == 0:
                return redirect('http://localhost:4600/')
            else:
                return redirect('http://localhost:4800/')
        elif check == 0:
            messages.error(request, "Your OTP is wrong")
            return render(request, 'verifyOTP.html', {'id': id})
        else:
            messages.error(request, "Your OTP is expire please click send OTP again to receive another")
            return render(request, 'verifyOTP.html', {'id': id})


def deleteFile(request):
    if request.method == "POST":
        current_id = request.POST['filedel']
        print(current_id)
        list_sharefile_id = ShareFile.objects.filter(file_id_id=current_id)
        list_sharefile_id_1 = list(list_sharefile_id)
        for row in list_sharefile_id_1:
            print(row)
            DRIVES.parents().delete(fileId=row.shareFileID, parentId='1JuyWaMD46VcLXtGJyKMR8jQWHl1X_OSq').execute()
            row.delete()
        fileid = File.objects.get(fileID=current_id)
        filedel = fileid.fileID
        f = drive.CreateFile({'id': filedel})
        f.Delete()
        fileid.delete()
        messages.success(request, "File Deleted")
        return HttpResponseRedirect('/profile/viewfile/')
    return render(request, 'profile.html', {})


def downloadfileInProfile(request):
    if request.method == "POST":
        path = r"D:\\"
        current_user = request.POST['filedown']
        name = request.POST['name']
        print(current_user)
        print(name)
        i = os.path.join(path, name)
        f = drive.CreateFile({'id': current_user, 'title': name})
        f.GetContentFile(i, 'application/pdf')
        decrypt_file_stored_on_Cloud2(current_user, i)
        messages.success(request, "Download Success")
        return HttpResponseRedirect('/profile/viewfile/')
    return render(request, 'profile.html', {})


def downloadfileInSharing(request):
    if request.method == "POST":
        # Download file ve de xu ly
        current_id = request.POST['filedown']
        name = request.POST['name']
        query = f"parents = '{'1JuyWaMD46VcLXtGJyKMR8jQWHl1X_OSq'}'"
        list_file = DRIVE.files().list(q=query).execute()
        for f in list_file.get('files', []):
            if f['id'] == current_id:
                f = drive.CreateFile({'id': current_id, 'title': name})
                f.GetContentFile(name, 'application/pdf')

                break
        decrypt_file_stored_on_Cloud(current_id, name)
        item = ShareFile.objects.latest('date_create')
        # Lay tu database
        # SharedFile table
        # Lay licensseID moi nhat tu database (row cuoi cung)
        try:
            licenseid = downloadFile.objects.latest('date_create')
            last_license_id = licenseid.licenseID
        except:
            last_license_id = 'abcdea'
        editable, printable, expDate, owner = item.editable, item.printable, item.expDate, item.owner_name
        # Login table
        username, phone = request.user.username, request.user.first_name
        # DownloadedFile table
        downloader = request.user.username
        # Tao license_id()
        license_id = create_license_id(last_license_id)

        # decrypt_file_stored_on_Cloud() chua lam
        synchronous_key = key_synchronous_generator(license_id, editable, printable, username, phone, owner)

        # download function()
        # download file ve server va lay duong dan cua file
        file_path = name
        # file ma hoa thay the file cu
        synchronous_encryption(file_path, synchronous_key)

        # tao gia tri hash cua file vua ma hoa
        hash_encrypted_file = compute_hash_file(file_path)

        # tao file json chua thong tin file
        json_path = './' + hash_encrypted_file + '.json'
        dict = {
            'license_id': license_id,
            'downloader': downloader,
            'editable': editable,
            'printable': printable,
            'expDate': str(expDate),
            'owner': owner
        }
        generate_json_file(json_path, hash_encrypted_file, dict)

        # file .json của user import
        file_path = './user.json'
        # username, phone lay tu Login table cua user do
        dict = {
            'username': downloader,
            'phone': phone
        }
        generate_json_file(file_path, 'User', dict)

        try:
            # Nen 2 file vao file zip
            filename = name + '.zip'
            with ZipFile(filename, 'w') as zipObj2:
                zipObj2.write(name)
                zipObj2.write(json_path)
                zipObj2.write(file_path)
            # Upload file len Cloud
            file_meta = {'name': filename, 'parents': ['1O0QxtqjUV0EZu-SZOWOcdBfTogVUpgTT']}
            media = MediaFileUpload(filename, mimetype='application/unknown', resumable=True)
            DRIVE.files().create(body=file_meta,
                                 media_body=media,
                                 fields='id').execute()
            query = f"parents = '{'1O0QxtqjUV0EZu-SZOWOcdBfTogVUpgTT'}'"
            filess = DRIVE.files().list(q=query).execute()
            for item in filess.get('files', []):
                downloadFile.objects.update_or_create(licenseID=license_id, sharefile_id=current_id,
                                                      fileID_zip=item['id'],
                                                      downloader=request.user.username)
        except Exception as e:
            print(e)
        # Download File zip ve user machine
        path = r'D:\\'
        i = os.path.join(path, filename)
        abc = downloadFile.objects.latest('date_create')
        f = drive.CreateFile({'id': abc.fileID_zip, 'title': filename})
        f.GetContentFile(i, 'application/unknown')
        messages.success(request, "Download Success")
        context = {'id': current_id}
    return render(request, 'downloadSuccessInSharing.html', context)


def re(request):
    if request.method == "POST":
        share = request.POST['shareid']
        # date_last = request.POST['date_create']
        a = ShareFile.objects.latest('date_create')
        a.shareFileID = share
        itemlist = DRIVE.files().get(fileId=a.shareFileID).execute()
        context = {'id': itemlist['id'], 'name': itemlist['name']}
    return render(request, 'share/profileSharing.html', context)


# OTP code:
def random_digit():
    random_code = ''.join(choice(digits) for i in range(10))
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
        dump(data, f, indent=4)


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


def file_is_not_existed(file_path):
    if not path.isfile(file_path) or read_file(file_path) == b'':
        return True
    else:
        return False


def OTP_generator(request):
    # Lay sessionID cua user
    # a = ShareFile.objects.latest('date_create')
    a = request.session
    session_id = a.session_key
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
    if file_is_not_existed('./OTP.json'):
        generate_json_file('./OTP.json', 'OTP', dict)
    else:
        append_json_file('./OTP.json', 'OTP', dict, session_id)

    return OTP_value


def OTP_verification(request, OTP_value):
    # Lay sessionID cua user
    a = request.session
    session_id = a.session_key
    data = None
    counter, OTP_check, time_create = None, None, None
    # Neu file ton tai va khac rong
    if file_is_not_existed('./OTP.json'):
        # print('OTP expires!!!')
        return -1
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
    # 2020 10 28 02 30 08 743182
    # 2020 10 28 02 35 08 743183
    if time_create is not None and int(time_verify) - int(time_create) <= 500000000:
        hotp = HOTP(base32secret)
        if hotp.verify(OTP_value, counter):

            return 1
        else:
            return 0
    else:
        return -1


def sendSMS():
    while True:
        try:
            time.sleep(5)
            sender_phone, messages = recevieSmsMessage()
            temp = messages.split()
            if temp[0] == 'v' or temp[0] == 'V':
                license_id_SMS = temp[1]
                # license_id_SMS = 'abcdeb'
                random_code_SMS = temp[2]
                try:
                    check = downloadFile.objects.get(licenseID=license_id_SMS)
                    downloader = check.downloader
                    username = User.objects.get(username=downloader).username
                    phone = User.objects.get(username=downloader).first_name
                    sharefile_id = check.sharefile_id
                    expDate = ShareFile.objects.get(shareFileID=sharefile_id).expDate
                    time1_string = datetime.now().strftime('%Y%m%d%H%M%S%f')
                    x = expDate.strftime('%Y%m%d%H%M%S%f')
                    # print(time1_string)
                    # print(x)
                    if int(x) - int(time1_string) > 0:
                        if phone == sender_phone:
                            # print(license_id_SMS, downloader, username, phone,
                            #       expDate, random_code_SMS)
                            otp_value = OTP_synchronous_generator(license_id_SMS, downloader, username, phone,
                                                                  expDate, random_code_SMS)
                            message = 'OTP value: ' + otp_value
                            sendSmsMessage(sender_phone, message)
                            # temp.clear()
                        else:
                            sendSmsMessage(sender_phone, "Cloud9: You don't have permission to view this file. "
                                                         "Please check your phone number again.")
                    else:
                        # check.delete()
                        sendSmsMessage(sender_phone, "Cloud9: Your file is expired.")
                except:
                    sendSmsMessage(sender_phone, "Cloud9: Sorry! This file's licensedID is wrong or have been revoked! "
                                                 "Try again or contact the owner!")
            else:
                print(temp[0], temp[1], temp[2])
                sendSmsMessage(sender_phone, "Cloud9: SMS syntax error. Please check and send message again.")

            temp.clear()
        except IndexError:
            continue


class EditProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'profile.html'


class SiteLogoutView(LogoutView):
    template_name = 'logout.html'
