from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('login2fa')
        else:
            return render(request, 'templates/login.html', {'error': 'Неверный логин или пароль'})
    return render(request, 'templates/login.html')

@login_required
def login2fa_view(request):
    return render(request, 'templates/login2fa.html')