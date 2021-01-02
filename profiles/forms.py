from django import forms
import re
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from .models import ShareFile
from django.core.validators import RegexValidator


class RegistrationForm(forms.Form):

    username = forms.EmailField(widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Google Email', 'required': True}),
                                validators=[RegexValidator('^[a-z0-9](\.?[a-z0-9]){5,}@g(oogle)?mail\.com$',
                                message="Please enter validate Gmail.")])
    phone = forms.CharField(max_length=10, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder':'Phone number', 'required':True}))
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder':'Password'}))
    password2 = forms.CharField(label='Rewrite Password', widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder':'Rewrite Password'}))

    def clean_password2(self):
        if 'password1' in self.cleaned_data:
            password1 = self.cleaned_data['password1']
            password2 = self.cleaned_data['password2']
            if password1 == password2 and password1:
                return password2
        raise forms.ValidationError("Invalid password")

    def clean_username(self):
        username = self.cleaned_data['username']
        try:
            User.objects.get(username=username)
        except ObjectDoesNotExist:
            return username
        raise forms.ValidationError("This username is existed")

    def clean_phone(self):
        phone = self.cleaned_data['phone']
        position = 0
        new_character = '+84'
        new_phone = new_character + phone[position + 1:]
        return new_phone

    def save(self):
        User.objects.create_user(username=self.cleaned_data['username'], password=self.cleaned_data['password1'],
                                 first_name=self.cleaned_data['phone'])

class PermisssionForm(forms.ModelForm):
    class Meta:
        model = ShareFile
        fields = ['shareEmails', 'editable', 'printable', 'downloadable', 'expDate']
        widgets = {
            'shareEmails': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'e.g abc@gmail.com'}),
            'editable': forms.Select(attrs={'class': 'form-control', 'font-color': 'black'}),
            'printable': forms.Select(attrs={'class': 'form-control'}),
            'downloadable': forms.Select(attrs={'class': 'form-control'}),
            'expDate': forms.DateTimeInput(attrs={'class': 'form-control'})
            # 'expDate': forms.DateTimeInput(attrs={'class': 'form-control', 'name': 'expDate'}),
        }
class UpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g 0123456789', 'maxlength': 12 })
        }

