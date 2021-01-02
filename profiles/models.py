
from django.db import models
from django.contrib.auth.models import User
# Create your models here.
from django.utils import timezone
from datetime import datetime 

class Drive(models.Model):
    driveID = models.TextField(primary_key=True)
    driveName = models.TextField(max_length=150)
    driveOwner = models.ForeignKey(to=User, on_delete=models.CASCADE)

class File(models.Model):
    fileID = models.TextField(primary_key=True)
    fileName = models.TextField(max_length=150)
    secretKey = models.TextField(default='')
    driveID = models.ForeignKey(to=Drive, on_delete=models.CASCADE)

class ShareFile(models.Model):
    choice = ((0, "Deny"), (1,"Accept"))
    shareFileID = models.TextField(primary_key=True)
    share_file_name = models.TextField(default='')
    editable = models.IntegerField(choices=choice, default=0)
    printable = models.IntegerField(choices=choice, default=0)
    downloadable = models.IntegerField(choices=choice, default=0)
    shareEmails = models.EmailField()
    link = models.TextField()
    date_create = models.DateTimeField(auto_now_add=True,blank=True)
    expDate = models.DateTimeField()
    file_id = models.ForeignKey(to=File, on_delete=models.CASCADE)
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    owner_name = models.TextField(default='')
    is_active = models.BooleanField(default=True)
class OTP(models.Model):
    otp_id = models.TextField(primary_key=True)
    date_create = models.DateTimeField(auto_now_add=True, blank=True)
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    file_id = models.ForeignKey(to=ShareFile,default='', on_delete=models.CASCADE)
    email = models.EmailField(default='')

class downloadFile(models.Model):
    licenseID = models.TextField(primary_key=True)
    downloader = models.TextField()
    sharefile = models.ForeignKey(to= ShareFile, on_delete=models.CASCADE)
    fileID_zip = models.TextField()
    date_create = models.DateTimeField(auto_now_add=True, blank=True)

class File_Analysis(models.Model):
    shareFileID = models.ForeignKey(to=ShareFile, on_delete=models.CASCADE, primary_key=True)
    UserID = models.ForeignKey(to=User, on_delete=models.CASCADE)
    reading_Time = models.IntegerField(default=0)
    reading_Count = models.IntegerField(default=0)







