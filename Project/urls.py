"""Project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from django.views.generic import TemplateView
from profiles import views as profiles_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('profile/view', profiles_views.viewOnline_Owner, name='viewowner'),
    path('', TemplateView.as_view(template_name="home.html"), name='index'),
    path('login/', profiles_views.login_request, name='login'),
    path('check/<str:file_id>/', profiles_views.login_check, name='logincheck'),
    path('register/', profiles_views.register, name='register'),
    path('profile/usr/', profiles_views.userProfile, name='usrprofile'),
    path('createfolder/', profiles_views.createFolder, name='create'),
    path('logout', profiles_views.SiteLogoutView.as_view(), name='logout'),
    path('profile/', profiles_views.EditProfileView.as_view(), name='profile'),
    path('profile/viewfile/', profiles_views.viewfilebyusername, name='view'),
    path('profile/viewDetail/', profiles_views.viewDetail, name='viewDetail'),
    path('profile/document/', TemplateView.as_view(template_name="document.html"), name='document'),
    path('profile/upinf/', profiles_views.upinf, name='upload'),
    path('profile/usr/changepassword/', profiles_views.change_password, name='change_password'),
    path('profile/downloadfile/', profiles_views.downloadfileInProfile, name='downloadInProfile'),
    path('profile/downloadFile/', profiles_views.downloadfileInSharing, name='download1'),
    path('profile/deletefile/', profiles_views.deleteFile, name='delete'),
    path('profile/viewlicensed/revoke', profiles_views.revokeFile_Offline, name='revoke'),
    path('profile/viewlicensed/revoKe', profiles_views.revokeFile_Online, name='revoKe'),
    path('profile/viewlicensed/', profiles_views.view_revoke, name='view_revoke'),
    path('viewlink/', profiles_views.createLink, name='createLink'),
    path('sendmail/', profiles_views.sendMail, name='sendmail'),
    path('create/', profiles_views.create, name='cr'),
    path('linkshare/<str:file_id>/', profiles_views.linkshare),
    path('sharefile/return/', profiles_views.re, name='returnshare'),
    path('back/', profiles_views.back, name='back'),
    path('otponline/', profiles_views.sendMailOTP, name='sendotp'),
    path('otpOnline/', profiles_views.sendmailOTP, name='sendOtp'),
    path('otponline/viewonline/', profiles_views.viewOnline, name='viewonline'),
    path('sharefile/', profiles_views.viewsharefile, name='viewsharefile'),
]
