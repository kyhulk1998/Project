from profiles.SMSgateway import sendSmsMessage, recevieSmsMessage
import time
from profiles.models import downloadFile, ShareFile
from django.contrib.auth.models import User
from datetime import datetime
from profiles.download_share_procedure import OTP_synchronous_generator
def sendSMS():
    while True:
        time.sleep(2)
        sender_phone, messages= recevieSmsMessage()
        temp = messages.split()
        if temp[0] == 'v' or temp[0] == 'V':
            license_id_SMS = temp[1]
            random_code_SMS = temp[2]
            check = downloadFile.objects.get(licenseID=license_id_SMS)
            # check.downloader = downloader
            # User.objects.get(username=downloader)
            if check is None:
                sendSmsMessage(sender_phone,"Your licensedID is wrong or revoked! Please send message again!")
            else:
                downloader = check.downloader
                username = User.objects.get(username=downloader).username
                #phone = User.objects.get(username=downloader).first_name
                phone = '0333721887'
                sharefile_id = check.sharefile_id
                expDate = ShareFile.objects.get(shareFileID=sharefile_id).expDate
                if expDate > datetime.now():
                    if phone == sender_phone:
                        sendSmsMessage(sender_phone, OTP_synchronous_generator(license_id_SMS, downloader, username, phone, expDate, random_code_SMS))
                        #temp.clear()
                    else:
                        sendSmsMessage(sender_phone, "You are not have pemission to view this file")
                else:
                    sendSmsMessage(sender_phone, "File is expired")


            #     sendSmsMessage(sender_phone,"You are not have pemission to view this file")
            # elif sender_phone != request.user.first_name:
            #     sendSmsMessage(sender_phone,"You use wrong phone number")



            #server nhan SMS- check cu phap - check licenseid từ  nhan trich xuat thong tin con lai trong DB- check ngay het han, phone number, downloader, goi OTP, gui OTP

            #downloader, username, phone, expDate
            # sendSmsMessage(sender_phone, OTP_synchronous_generator())
            # temp.clear()
        else:
            print(temp[0], temp[1], temp[2])
            sendSmsMessage(sender_phone, "SMS syntax error")

        temp.clear()
sendSMS()