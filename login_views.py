import email
import threading

import password
from django.contrib import messages
from django.contrib.auth import authenticate, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.template import context
from django.template.context_processors import request
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.views.generic import View
from validate_email import validate_email

from .utils import generate_token


# I am gonna create my views here


class EmailThread(threading.Thread):

    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

    class RegistationView(View):
        def get (self, request):
            return render(request, 'Auth/register.html')

        def post(self, request):

            context = {

                'data' :request.POST,
                'has_error':False
            }


        Username = request.POST.get('Username')
        email = request.POST.get('Email')
        password= request.POST.get('Password')
        password2= request.POST.get('Password2')
        full_name= request.POST.get('name')

if len(password) < 6:
    messages.add_message(request, messages.ERROR,
                         'Password too short')
    context['has_error'] = True

if password != password2:
    messages.add_message(request, messages.ERROR,
            'Password dont match each other')
    context['has_error'] = True


if not validate_email(email):
        messages.add_message(request, messages.ERROR, 'Email is in use')
context['has_error'] = True

try:
    if User.objects.get(email=email):
            messages.add_message(request, messages.ERROR, 'Username is already in use' )
            context['has_error'] = True

except Exception as identifier:
    pass

if context['has_error']:
    return render(request, 'autho/register.html', context, status=400)

    user =User.objects.create_user(username=username, email=email)

    user.set_password(password)
    user.first_name = full_name
    user.last_name = full_name
    user.is_active =False
    user.save()

    current_site=get_current_site(request)
    email_subject = 'Activate your account'
    message= render_to_string('autho/activate.html',
                              {
                                  'user': user,
                                  'domain': current_site.domain,
                                  'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                  'token': generate_token.make_token(user)
                              }
                              )
    email_message = EmailMessage(
        email_subject,
        message,
        settings.EMAIL_HOST_USER,
        [email]
        )

    EmailThread(email_message).start()
    messages.add_message(request, messages.SUCCESS,
                         'Account created successfully')

     return redirect('login')


class loginview(View):
    def get(self, request):
        return render(request, 'author/login.html' )

def post(self, request):
    context = {
        'data': request.POST,
        'has_error': False
    }
    username = request.POST.get('username')
    password = request.POST.get('password')

    if username == '':
        messages.add_message(request, messages.ERROR,
                            'Username is required')
    context['has_error'] = True

    if password == '':
        messages.add_message(request, messages.ERROR,
                             'Password is required')
    context['has_error'] = True

    user = authenticate(request, username=username, password=password)

if not User and not context['has_error']:
    messages.add_message(request, messages.ERROR,
                         'login not valid')
context['has_error'] = True

if not User and not context['has_error']:
    messages.add_message(request, messages.ERROR, 'Invalid login')
    context['has_error'] = True

if context['has_error']:
    return render(request, 'autho/login.html', status=401, context=context)
    login(request, User)
    return redirect('home')


class ActivateAccountView(View):
 def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS,
                                 'account activated successfully')
            return redirect('login')
        return render(request, 'auth/activate_failed.html', status=401)

class Homepage(View):
    def get(self, request):
     return render(request, 'home.html')

class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout successfully')
        return redirect('login')


