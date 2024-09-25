from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django_otp_webauthn.models import WebAuthnCredential

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('register_passkey')
        elif user is not None and WebAuthnCredential.objects.filter(user=request.user).exists():
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'templates/login.html', {'error': 'Неверный логин или пароль'})
    return render(request, 'templates/login.html')

def passreg_view(request):
    return render(request, 'templates/register_passkey.html')
@login_required
def dashboard_view(request):
    return render(request, 'templates/dashboard.html',  {'username': request.user.username})
