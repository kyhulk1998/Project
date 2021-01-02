from django.contrib import admin
from .models import Drive,File,ShareFile,OTP,downloadFile
# Register your models here.

admin.site.register(Drive)
admin.site.register(File)
admin.site.register(ShareFile)
admin.site.register(OTP)
admin.site.register(downloadFile)