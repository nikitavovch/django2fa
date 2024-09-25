from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django_otp_webauthn.models import WebAuthnCredential


def login_view(request):
    next_url = request.GET.get('next', 'dashboard')  # По умолчанию перенаправляем на 'dashboard'

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            if WebAuthnCredential.objects.filter(user=user).exists():
                return redirect(next_url)
            else:
                return redirect('register_passkey')  # Если Passkey нет, регистрируем
        else:
            return render(request, 'templates/login.html', {'error': 'Неверный логин или пароль'})

    return render(request, 'templates/login.html')


@login_required
def passreg_view(request):
    next_url = request.GET.get('next', 'dashboard')  # Для следующего перенаправления после регистрации Passkey
    return render(request, 'templates/register_passkey.html', {'next': next_url})


@login_required
def dashboard_view(request):
    return render(request, 'templates/dashboard.html', {'username': request.user.username})
