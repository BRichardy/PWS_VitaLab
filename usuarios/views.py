from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib import messages
from django.contrib.messages import constants
from django.contrib.auth.decorators import login_required

def cadastro(request):
    if request.method == 'GET':
        return render(request, 'usuarios/cadastro.html')
    elif request.method == 'POST':
        primeiro_nome = request.POST.get('primeiro_nome')
        ultimo_nome = request.POST.get('ultimo_nome')
        username = request.POST.get('username')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirmar_senha')
        
        if not senha == confirmar_senha:
            messages.add_message(request, constants.ERROR, 'As senhas não coincidem')
            return redirect('/user/cadastro')

        if len(senha) <= 0 :
            messages.add_message(request, constants.ERROR, 'Senha inválida')
            return redirect('/user/cadastro')
        
        usuario = User.objects.filter(username=username).filter(email=email)
        
        if len(usuario) > 0:
            messages.add_message(request, constants.ERROR, 'Username ou E-Mail já utilizado')
            return redirect('/user/cadastro')
        else:
            try:
                #Username deve ser único
                user = User.objects.create_user(
                    first_name = primeiro_nome,
                    last_name = ultimo_nome,
                    username = username,
                    email = email,
                    password = senha
                )
            except:
                return redirect('/user/cadastro')
        
        messages.add_message(request, constants.SUCCESS, 'Usuário cadastrado com sucesso')
        return redirect('/user/cadastro')
        
def login(request):
    if request.method == 'GET':
        return render(request, 'usuarios/login.html')
    elif request.method == 'POST': 
        username = request.POST.get('username')
        senha = request.POST.get('senha')
        
        user = authenticate(username=username, password=senha)
        
        if user:
            login(request, user)
            return redirect('/')
        else:
            messages.add_message(request, constants.ERROR, 'Usuário ou senha inválidos')
            return redirect('/user/login')


@login_required
def teste(request):
    return HttpResponse('Teste')
        
        