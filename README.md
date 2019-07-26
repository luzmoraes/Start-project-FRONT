# Fullstack project with Laravel 5.8 and Angular 8
Step by step example project with api in Laravel 5.8, front with Angular 8 and authentication with JWT.

---
# ATUALIZAR TUTORIAL A PARTIR DAQUI
---
### Instalando Angular e AdminLTE
Podemos criar uma aplicação angular do zero com ng-CLI (ng new my-app), porém iremos utilizar um painel pronto, o [AdminLTE](https://adminlte.io/) através do seu repositório no [GitHub](https://github.com/csotomon/Angular2-AdminLTE).
1. Copiar a url para clonar o AdminLTE na pasta raiz do nosso projeto (fora da pasta api que criamos).
```
git clone https://github.com/csotomon/Angular2-AdminLTE.git
```
2. Renomear a pasta da aplicação criada para “web”.
3. Rodar o __npm install__.
4. Dentro da pasta __web/src/environments__, no arquivo __environment.ts__, onde criamos nossas constantes no Angular, vamos criar uma constante para nossa api.
```
api_url: 'http://localhost:8000/api'
```
__OBS.:__ No arquivo __environment.prod.ts__ definimos as urls de produção.

### Alterando as rotas
__Vamos usar somente a parte do painel, onde todas as seções, exceto o Login, serão privadas.__
1. Em __app.modules.ts__ limpar e deixar apenas o __AppComponent__, com isso não vamos mais carregar os __starter__.
2. Em app criar o módulo __auth__, que usaremos para autenticação:
```
ng g module auth
```
* importar no app.modules.ts.
3. Dentro da pasta do módulo auth vamos criar um componente chamado __login__ e declará-lo no módulo auth.
```
ng g component auth/login
```
4. Trocar as rotas da aplicação inicial em __app/app-routing/app-routing.modules.ts__.
```
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { LoginComponent } from '../auth/login/login.component';

@NgModule({
  imports: [
    RouterModule.forRoot([
      { path: '', redirectTo: 'admin', pathMatch: 'full' },
      { path: 'auth/login', component: LoginComponent },
    ])
  ],
  declarations: [],
  exports: [ RouterModule]
})
export class AppRoutingModule { }
```

### Formulário de login
1. Criar o formGroup no component login;
2. Importar o módulo ReactiveFormsModule no auth.module.ts
3. Criar o formulário login.component.html
__HTML__
```
<div class="container app-login">
  <div class="row">
    <div class="col-xs-12 col-md-6 col-md-offset-3">
      <div class="panel panel-default">
        <div class="panel-body">
          <h1 class="text-center">
            <b>TJG</b> Web
            <br/>
            <small>Área Restrita</small>
          </h1>
          <br/>
          <div class="alert alert-danger alert-dismissible" role="alert" *ngIf="errorCredentials">
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
            Usuário ou senha inválidos.
          </div>
          <form [formGroup]="f" novalidate>
            <div class="form-group has-feedback" [ngClass]="{'has-success': f.controls['email'].valid,
                'has-error': f.controls['email'].invalid && (f.controls['email'].touched || f.controls['email'].dirty)}">
              <input type="email" formControlName="email" class="form-control" id="InputEmail" placeholder="Email">
              <span *ngIf="f.controls['email'].valid" class="glyphicon glyphicon-ok form-control-feedback" aria-hidden="true"></span>
              <span *ngIf="f.controls['email'].invalid && (f.controls['email'].touched || f.controls['email'].dirty)">
                <span class="glyphicon glyphicon-remove form-control-feedback" aria-hidden="true"></span>
                <span class="text-danger">E-mail inválido.</span>
              </span>
            </div>
            <div class="form-group" [ngClass]="{'has-success': f.controls['password'].valid,
                 'has-error': f.controls['password'].invalid && (f.controls['password'].touched || f.controls['password'].dirty)}">
              <input type="password" formControlName="password" class="form-control" id="InputPassword" placeholder="Password">
              <span class="text-danger" *ngIf="f.controls['password'].invalid && (f.controls['password'].touched || f.controls['password'].dirty)">Campo obrigatório.</span>
            </div>
            <button type="submit" class="btn btn-default" [disabled]="f.invalid" (click)="onSubmit()">Entrar</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
```

__CSS__
```
.app-login .row{margin-top: 20vh;}
.app-login .panel-body{box-shadow: 0px 0px 10px 3px #ccc;}
```

### Criando serviço de autenticação
1. criar, na pasta __auth__, o serviço que validará as rotas.
```
ng g service services/auth
```
2. Registrar o serviço no módulo auth:
```
@NgModule({
 imports: [
   CommonModule,
   ReactiveFormsModule
 ],
 declarations: [
   LoginComponent
 ],
 providers: [
   AuthService
 ]
})
```
3. No serviço de autenticação criar o método de login que receberá as informações do formulário e requisitará a autenticação a Api;
4. Importar o __HttpClient__ que fará nossas requisições a Api;
5. Importar o __environment__ onde declaramos nossas constantes;
```
login(credentials: {email: string, password: string}) {
   return this.http.post('${environment.api_url}/auth/login', credentials);
 }
```
6. No componente login, chamar o serviço de autenticação, método login.
    - No construtor importar o serviço de autenticação

 ### Ativando CORS no Laravel
Instalar a biblioteca [https://github.com/barryvdh/laravel-cors](https://github.com/barryvdh/laravel-cors) na nossa Api.
```
composer require barryvdh/laravel-cors
```
2. Registrar um grupo de middleware:
*Podemos registar de forma __global__, __web__ ou __api__, como estamos usando o laravel somente como __api__ é nela que iremos registrar.*
```
Api / App / Http / Kernel.php
\Barryvdh\Cors\HandleCors::class
```
Publicar o arquivo de configuração que será gerado na pasta __config__.
```
php artisan vendor:publish --provider="Barryvdh\Cors\ServiceProvider"
```
O arquivo gerado foi o __cors.php__ nele serão feitas as configurações de cabeçalho.
Liberar a proteção __CSRF__, em *Api / App / Http / Middleware / VerifyCsrfToken*
```
protected $except = [
    'api/*'
];
```
### Armazenando token

1. No método __login__ interceptar a resposta com o __.do()__, para usar esse método será preciso tipar a requisição post, usar o __<any>__.
2. Criar um __hash base 64__ para os dados do usuário que ficará no localStorage, usar o método __btoa()__ para isso.
3. No componente login serão tratados os erros caso ocorra.
4. Criar no serviço o método que checa se o usuário tá logado.

#### Finalizando AuthService e Mostrando dados do usuário
1. Criar uma interface (model) para o nosso user;
```
export interface User {
id: number;
name: string;
email: string;
created_at: string;
updated_at: string;
}
```
### Guarda de Rotas
1. Criar um serviço para os __*guardas*__ das nossas rotas;
```
ng g service guards/auth
```
2. Renomear o arquivo de __auth.service.ts__ para __auth.guard.ts__ e o nome da classe de __AuthService__ para __AuthGuard__ de acordo com o style guide do Angular.
*O site do Angular, em Guards, ele mostra algumas interfaces, use a __CanActivate__*.

2. Implementar a classe AuthGuard a esse método.
```
import { Observable } from 'rxjs/Observable';
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router, CanActivateChild } from '@angular/router';
import { AuthService } from './../auth/services/auth.service';

@Injectable()
export class AuthGuard implements CanActivate, CanActivateChild {

 constructor(private auth: AuthService, private router: Router) { }

 canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
   if ( this.auth.check() ) {
     return true;
   }
   this.router.navigate(['auth/login']);
   return false;
 }

 canActivateChild(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
   if ( this.auth.check() ) {
     return true;
   }
   this.router.navigate(['auth/login']);
   return false;
 }

}
```
__Como ele será um serviço global, importá-lo no provider do app.module.__

4. Nas rotas de administrador *(admin/admin-routing)* inserir o serviço de guardião de rotas.
```
import { AdminDashboard2Component } from './../admin-dashboard2/admin-dashboard2.component';
import { AdminDashboard1Component } from './../admin-dashboard1/admin-dashboard1.component';
import { AdminComponent } from './../admin.component';
import { NgModule, Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { AuthGuard } from '../../guards/auth.guard';

@NgModule({
 imports: [
   RouterModule.forChild([
     {
       path: 'admin',
       component: AdminComponent, canActivate: [AuthGuard], canActivateChild: [AuthGuard],
       children: [
         {
           path: '',
           redirectTo: 'dashboard1',
           pathMatch: 'full'
         },
         {
           path: 'dashboard1',
           component: AdminDashboard1Component
         },
         {
           path: 'dashboard2',
           component: AdminDashboard2Component
         }
       ]
     }
   ])
 ],
 exports: [
   RouterModule
 ]
})
export class AdminRoutingModule { }
```
__OBS.:__ Essa verificação não está segura, pois se o usuário criar direto no localStorage um usuário com um valor qualquer ele vai ter acesso a rota restrita, pois tá verificando apenas se existe a sessão user.

### Adicionando token no header da requisição

O __intercept__ foi incluído a partir da versão 4.3 do Angular, usar o mesmo para evitar de passar em toda requisição um options com o header.

1. Em app criar um diretório chamado __interceptors__ e dentro dele um arquivo chamado __token.interceptor.ts__;
2. Copiar o código da documentação do angular *(FUNTAMENTALS >> HttpClient >> Intercepting requests and responses)*: [https://angular.io/guide/http#intercepting-requests-and-responses](https://angular.io/guide/http#intercepting-requests-and-responses)
3. Alterar o nome da classe para __TokenInterceptor__, o que essa classe irá fazer?
Sempre que tiver uma requisição, ela irá interceptar essa requisição e adicionar o Token ao header da requisição.
```
import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { environment } from '../../environments/environment';

/** Pass untouched request through to the next request handler. */
@Injectable()
export class TokenInterceptor implements HttpInterceptor {

 intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
   const requestUrl: Array<any> = request.url.split('/');
   const apiUrl: Array<any> = environment.api_url.split('/');
   const token = localStorage.getItem('token');
   /* verifica se a requisição é para a api da aplicação */
   if (token && (requestUrl[2] === apiUrl[2])) {
     const newRequest = request.clone({ setHeaders: {'Authorization': `Bearer ${token}`} });
     return next.handle(newRequest);
   }else {
     return next.handle(request);
   }
 }

}
```
__OBS.:__ Esse conceito de __interceptor__ funciona com o mesmo conceito do __middleware__ do Laravel.

4. Importar nosso interceptor no app.module:
```
providers: [
   AuthGuard,
   { provide: HTTP_INTERCEPTORS, useClass: TokenInterceptor, multi: true },
 ],
```

### Refresh Token

1. Duplicar o __token.interception.ts__ e renomear para __refresh-token.interception.ts__.
Ao contrário do __token.interception__, que intercepta o request antes da requisição, o __refresh-token.interception__ irá interceptar após a requisição, utilizando o operador __catch do rxjs__, se o token estiver expirado ele fará uma nova requisição para atualizar o token, se o tempo limite de expiração do token não tiver expirado ele carrega os dados de acordo com a requisição.
__Para repetir a primeira requisição após requisitar a atualização do token é usado o operador flatMap do rxjs.__
```
import { Injectable, Injector } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpErrorResponse, HttpClient } from '@angular/common/http';
import { environment } from './../../environments/environment';
// tslint:disable-next-line:import-blacklist
import { Observable } from 'rxjs/Rx';

@Injectable()
export class RefreshTokenInterceptor implements HttpInterceptor {

 constructor(private injector: Injector) {}

 intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

   return next.handle(request).catch((errorResponse: HttpErrorResponse) => {
     const error = (typeof errorResponse.error !== 'object') ? JSON.parse(errorResponse.error) : errorResponse;

     if (errorResponse.status === 401 && error.error === 'token_expired') {
       const http = this.injector.get(HttpClient);

       return http.post<any>(`${environment.api_url}/auth/refresh`, {})
         .flatMap(data => {
           localStorage.setItem('token', data.token);
           const cloneRequest = request.clone({setHeaders: {'Authorization': `Bearer ${data.token}`}});

           return next.handle(cloneRequest);
         });
     }

     return Observable.throw(errorResponse);
   });

 }
}
```

### Tratando outros erros de token
Criar na raiz do app um arquivo chamado __app.error-handle.ts__, nele será tratado outros erros de token retornados do handle da nossa api.
```
import { Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, ErrorHandler, Injector } from '@angular/core';

@Injectable()
export class AplicationErrorHandle extends ErrorHandler {

  constructor(private injector: Injector) {
    super();
  }

  handleError(errorResponse: HttpErrorResponse | any) {
    if (errorResponse instanceof HttpErrorResponse) {
      const error = (typeof errorResponse.error !== 'object') ? JSON.parse(errorResponse.error) : errorResponse.error;

      if (errorResponse.status === 400 &&
        (error.error === 'token_expired' || error.error === 'token_invalid' ||
          error.error === 'A token is required' || error.error === 'token_not_provided')) {
        this.goToLogin();
      }

      if (errorResponse.status === 401 && error.error === 'token_has_been_blacklisted') {
        this.goToLogin();
      }

    }

    super.handleError(errorResponse);
  }

  goToLogin(): void {
    const router = this.injector.get(Router);
    router.navigate(['auth/login']);
  }

}

```
