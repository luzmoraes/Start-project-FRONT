# Fullstack project with Laravel 5.8 and Angular 8
Step by step example project with api in Laravel 5.8, front with Angular 8 and authentication with Laravel Passport.

---

### Verificando a versão do Angular CLI
```sh
$ ng --version
```
Se a versão for < que a 8 atualize para versão 8 (8.1.3 no momento).
```sh
$ npm uninstall -g @angular/cli
$ npm cache clean
# if npm version is > 5 then use `npm cache verify` to avoid errors (or to avoid using --force)
$ npm install -g @angular/cli@latest
```

### Criando o projeto (FRONT)

```sh
$ ng new start-project-front
# Would you like to add Angular routing? Yes
# Which stylesheet format would you like to use? SCSS
$ cd start-project-front
```

### Instalando o Bootstrap
##### Opção 1 (JQuery)

```sh
$ npm install bootstrap@4 jquery --save
```
As partes JavaScript do Bootstrap são dependentes do jQuery. Então você precisa do arquivo de biblioteca jQuery JavaScript também.
Em seguida adicione no seu arquivo __angular.json__.
```
"styles": [
    "src/styles.css","node_modules/bootstrap/dist/css/bootstrap.min.css"
],
"scripts": [
    "node_modules/jquery/dist/jquery.min.js",
    "node_modules/bootstrap/dist/js/bootstrap.min.js"
]
```

#####  Opção 2 (ng-bootstrap)
__ng-bootstrap__ Ele contém um conjunto de diretivas Angulares nativas com base na marcação e no CSS do Bootstrap. Como resultado, não depende do JavaScript do jQuery ou do Bootstrap.
```sh
$ npm install --save @ng-bootstrap/ng-bootstrap
```

Após a instalação, importe-o no seu módulo raiz e registre-o no array @NgModule imports.
```
import {NgbModule} from '@ng-bootstrap/ng-bootstrap';
@NgModule({
    declarations: [AppComponent, ...],
    imports: [NgbModule.forRoot(), ...],
    bootstrap: [AppComponent]
})
```

Agora instale o bootstrap 4 requerido pelo ng-bootstrap.
```sh
$ npm install bootstrap@4  --save 
```
Em seguida adicione no seu arquivo __angular.json__.
```
"styles": [
    "src/styles.css",
    "node_modules/bootstrap/dist/css/bootstrap.min.css"
],
```

##### Opção 3 (ngx-bootstrap)
[ngx-bootstrap gitHub](https://github.com/valor-software/ngx-bootstrap/blob/development/docs/getting-started/ng-cli.md)
[ngx-bootstrap documentation](https://valor-software.com/ngx-bootstrap/#/documentation#getting-started)
Adicionar o __ngx-bootstrap__ e o __bootstrap__.
```sh
$ npm install ngx-bootstrap bootstrap --save
```

Em seguida adicione no seu arquivo __angular.json__.
```
 "styles": [
    "./node_modules/bootstrap/dist/css/bootstrap.min.css", 
    "styles.css",
],
```

Exemplo de utilização do __ngx-bootstrap__:
Abrir ```src/app/app.module.ts``` e incluir:
```
import { AlertModule } from 'ngx-bootstrap';
...

@NgModule({
   ...
   imports: [AlertModule.forRoot(), ... ],
   ...
})
```

Abrir ```src/app/app.component.html``` e incluir:
```
<alert type="success">hello</alert>
```

Execute o projeto.
```sh
$ ng serve
```

### Criando os templates (layouts) que usaremos
##### blank - *não possui o header e o footer, usaremos nas telas de login e erros;*
##### full - *possui o header e o footer, usaremos nas telas protegidas;*

Dentro da pasta __app__ vamos criar uma pasta __layouts__ e em seguida vamos criar nossos templates:

#### blank
```sh
$ ng g c layouts/blank --skipTests
```

Altere o arquivo __blank.component.html__ conforme abaixo:
```
<!-- ============================================================== -->
<!-- Only router without any element -->
<!-- ============================================================== -->
<router-outlet></router-outlet>
```

#### full
```sh
$ ng g c layouts/full --skipTests
```

Altere o arquivo __full.component.html__ conforme abaixo:
```
<app-header-navigation></app-header-navigation>
<router-outlet></router-outlet>
```

#### Criando o header chamado no layout full
```sh
$ ng g c shared/header-navigation --skipTests
```
__Por enquanto não vamos editar o header criado!__

#### Dentro da pasta "shared" vamos criar o Spinner, que fará o load entre as páginas:
Vamos criar esse processo de forma manual:
1. botão direito na pasta __shared__ new file;
2. de o nome de: __spinner.component.ts__
3. o __gif__ chamado no spinner encontra-se na pasta __assets/images/loading.gif__ deste repositório.

Edite o arquivo __spinner.component.ts__
```
import {
    Component,
    Input,
    OnDestroy,
    Inject,
    ViewEncapsulation
} from '@angular/core';
import {
    Router,
    NavigationStart,
    NavigationEnd,
    NavigationCancel,
    NavigationError
} from '@angular/router';
import { DOCUMENT } from '@angular/common';

@Component({
    selector: 'app-spinner',
    template: `
        <div class="preloader" *ngIf="isSpinnerVisible">
            <div class="spinner">
                <img src="assets/images/loading.gif" alt="">
            </div>
        </div>`,
    encapsulation: ViewEncapsulation.None
})
export class SpinnerComponent implements OnDestroy {
    public isSpinnerVisible = true;

    @Input() public backgroundColor = 'rgba(0, 115, 170, 0.69)';

    constructor(
        private router: Router,
        @Inject(DOCUMENT) private document: Document
    ) {
        this.router.events.subscribe(
            event => {
                if (event instanceof NavigationStart) {
                    this.isSpinnerVisible = true;
                } else if (
                    event instanceof NavigationEnd ||
                    event instanceof NavigationCancel ||
                    event instanceof NavigationError
                ) {
                    this.isSpinnerVisible = false;
                }
            },
            () => {
                this.isSpinnerVisible = false;
            }
        );
    }

    ngOnDestroy(): void {
        this.isSpinnerVisible = false;
    }
}
```

#### Vamos importar os componentes criados no módulo global (app.module.ts)
```
import { SpinnerComponent } from './shared/spinner.component';
import { BlankComponent } from './layouts/blank/blank.component';
import { FullComponent } from './layouts/full/full.component';
import { HeaderNavigationComponent } from './shared/header-navigation/header-navigation.component';

@NgModule({
  declarations: [
    AppComponent,
    SpinnerComponent,
    BlankComponent,
    FullComponent,
    HeaderNavigationComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

### Criando a tela de login
```sh
$ ng g c login --skipTests
```
Vamos criar manualmente o __module__ e __route__ independentes para o component __login__:
1. botão direito na pasta login e new file __login.module.ts__;
```
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { LoginRoutes } from './login.routing';
import { LoginComponent } from './login.component';

@NgModule({
  imports: [
    FormsModule,
    ReactiveFormsModule,
    CommonModule,
    RouterModule.forChild(LoginRoutes)
  ],
  declarations: [
    LoginComponent
  ]
})
export class LoginModule { }
```

2. botão direito na pasta login e new file __login.routing.ts__;
```
import { Routes } from '@angular/router';
import { LoginComponent } from './login.component';

export const LoginRoutes: Routes = [
    {
        path: '',
        children: [
            {
                path: '',
                component: LoginComponent,
                data: {
                    title: 'Login',
                    urls: [
                        { title: 'Login', url: '/' },
                        { title: 'Login' }
                    ]
                }
            }
        ]
    }

];
```

#### login.component.html
```
<div class="container">
    <form class="form-signin" [formGroup]="formGroupLogin" (ngSubmit)="onSubmitLogin()" novalidate>
        <div class="text-center mb-4">
            <h1>LOGIN</h1>
        </div>

        <div class="form-label-group">
            <input type="text" class="form-control" placeholder="Email" required autofocus
                [ngClass]="{ 'input-error': ( formGroupLogin.get('username').dirty && formGroupLogin.get('username').hasError('required') ) }"
                name="username" id="username" formControlName="username">
            <label for="username">Email</label>
        </div>

        <div class="form-label-group">
            <input type="password" class="form-control" placeholder="Senha de acesso" required
                [ngClass]="{ 'input-error': ( formGroupLogin.get('password').dirty && formGroupLogin.get('password').hasError('required') ) || ( formGroupLogin.get('password').dirty && formGroupLogin.get('password').hasError('minlength') ) || ( formGroupLogin.get('password').dirty && formGroupLogin.get('password').hasError('maxlength') ) }"
                name="password" id="password" formControlName="password">
            <label for="password">Senha de acesso</label>
        </div>
        <button type="submit" class="btn btn-lg btn-primary btn-block" [disabled]="submitted">Entrar <img
                src="assets/images/loading_login.gif" alt="" *ngIf="submitted"></button>
        <p class="mt-5 mb-3 text-muted text-center">&copy; 2017 Linha Direta Company</p>
        <div class="alert alert-danger" *ngIf="errorCredentials">
            <strong>Erro!</strong> Email ou senha inválidos.
        </div>
    </form>
</div>
```

#### login.component.scss
```
.container {
    position: absolute;
    top: 0;
    left: 0;
    bottom: 0;
    right: 0;
  }
  .form-control {
      height: calc(48px + 2px);
  }
  
  .form-signin {
      width: 100%;
      max-width: 420px;
      padding: 15px;
      margin: 0 auto;
      top: 50%;
      transform: translateY(-50%);
      position: relative;
    }
    
    .form-label-group {
      position: relative;
      margin-bottom: 16px;
    }
    
    .form-label-group > input,ng g c dashboard --skipTests
    .form-label-group > label {
      padding: 12px 12px;
    }
    
    .form-label-group > label {
      position: absolute;
      top: 0;
      left: 0;
      display: block;
      width: 100%;
      margin-bottom: 0; /* Override default `<label>` margin */
      line-height: 1.5;
      color: #495057;
      border: 1px solid transparent;
      border-radius: 4px;
      transition: all .1s ease-in-out;
    }
    
    .form-label-group input::-webkit-input-placeholder {
      color: transparent;
    }
    
    .form-label-group input:-ms-input-placeholder {
      color: transparent;
    }
    
    .form-label-group input::-ms-input-placeholder {
      color: transparent;
    }
    
    .form-label-group input::-moz-placeholder {
      color: transparent;
    }
    
    .form-label-group input::placeholder {
      color: transparent;
    }
    
    .form-label-group input:not(:placeholder-shown) {
      padding-top: calc(12px + 12px * (2 / 3));
      padding-bottom: calc(12px / 3);
    }
    
    .form-label-group input:not(:placeholder-shown) ~ label {
      padding-top: calc(.12px / 3);
      padding-bottom: calc(12px / 3);
      font-size: 12px;
      color: #777;
    }
  
  .btn {
    img {
      width: 26px;
      position: absolute;
      right: 25px;
    }
  }

  .logo {
      width: 80%;
  }
```

#### login.component.ts
```
import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, FormControl, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../_services/auth.service';
import { environment } from '../../environments/environment';
import { HttpErrorResponse } from '@angular/common/http';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  submitted: boolean = false;
  errorCredentials: boolean = false;

  username = new FormControl('', [
    Validators.required
  ]);

  password = new FormControl('', [
    Validators.required
  ]);


  formGroupLogin: FormGroup = this.builder.group({
    username: this.username,
    password: this.password,
  });

  constructor(
    private builder: FormBuilder,
    private router: Router,
    private authService: AuthService
  ) { }

  ngOnInit() {
  }

  onSubmitLogin() {
    this.submitted = true;
    const dataForm = this.formGroupLogin.value;
    const data = environment.clientInfo;
    data.username = dataForm.username;
    data.password = dataForm.password;

    this.authService.login(data).subscribe(
      (token) => {
        if (token) {
          this.authService.getCurrentUser().subscribe(user => {
            this.router.navigate(['dashboard']);
          })
        } else {
          this.errorCredentials = true;
          this.submitted = false;
          setTimeout(() => {
            this.errorCredentials = false;
          }, 5000);
        }
      },
      (errorResponse: HttpErrorResponse) => {
        if (errorResponse.status === 401) {
          this.errorCredentials = true;
          this.submitted = false;
          setTimeout(() => {
            this.errorCredentials = false;
          }, 5000);
        }
        if (errorResponse.status === 500) {
          this.router.navigate(['error/internal-serve-error']);
        }
      }
    );

  }

}
```

### Vamos criar um módulo de erros para página não encontrata e para error interno de servidor
```sh
$ ng g c error/not-found --skipTests
$ ng g c error/internal-serve-error --skipTests
```
Vamos criar manualmente o __module__ e __route__ independentes para o component __error__:
1. botão direito na pasta error e new file __error.module.ts__;
```
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { FormsModule } from '@angular/forms';
import { Routes, RouterModule } from '@angular/router';

import { ErrorRoutes } from './error.routing';
import { NotFoundComponent } from './not-found/not-found.component';
import { InternalServeErrorComponent } from './internal-serve-error/internal-serve-error.component';

@NgModule({
  imports: [
    FormsModule,
    CommonModule,
    RouterModule.forChild(ErrorRoutes)
  ],
  declarations: [
    NotFoundComponent,
    InternalServeErrorComponent
  ]
})
export class ErrorModule { }
```

2. botão direito na pasta error e new file __error.routing.ts__;
```
import { Routes } from '@angular/router';
import { NotFoundComponent } from './not-found/not-found.component';
import { InternalServeErrorComponent } from './internal-serve-error/internal-serve-error.component';

export const ErrorRoutes: Routes = [
    {
        path: '',
        children: [
            {
                path: 'not-found',
                component: NotFoundComponent
            },
            {
                path: 'internal-serve-error',
                component: InternalServeErrorComponent
            }
        ]
    }

];
```

##### not-found.component.html
```
<h1>404</h1>
<h3>PÁGINA NÃO ENCONTRADA</h3>
```

##### internal-serve-error.component.html
```
<h1>500</h1>
<h3>INTERNAL SERVER ERROR</h3>
```

#### Alterando o arquivo app.routing.ts para dividir as rotas em públicas e privadas (precisa de autenticação)
##### Primeiro vamos criar só as rotas públicas e o redirecionamento para página não encontrada
##### app.routing.ts
```
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { BlankComponent } from './layouts/blank/blank.component';

export const AppRoutingModule: Routes = [
  {
    path: '',
    component: BlankComponent,
    children: [
      {
        path: '',
        redirectTo: '/login',
        pathMatch: 'full'
      },
      {
        path: 'login',
        loadChildren: './login/login.module#LoginModule',
      },
      {
        path: 'error',
        loadChildren: './error/error.module#ErrorModule',
      },
    ]
  },
  {
    path: '**',
    redirectTo: '/error/not-found'
  }
];
```

##### altere o arquivo app.module.ts, alterando a forma de importar as rotas, através do RouterModule
```
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

import { SpinnerComponent } from './shared/spinner.component';
import { BlankComponent } from './layouts/blank/blank.component';
import { FullComponent } from './layouts/full/full.component';
import { HeaderNavigationComponent } from './shared/header-navigation/header-navigation.component';

@NgModule({
  declarations: [
    AppComponent,
    SpinnerComponent,
    BlankComponent,
    FullComponent,
    HeaderNavigationComponent,
  ],
  imports: [
    BrowserModule,
    FormsModule,
    RouterModule.forRoot(AppRoutingModule, { useHash: false }),
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```
### Vamos criar uma interface para o token
```sh
$ ng g interface _interfaces/token

export interface Token {
    token_type: string;
    expires_in: number;
    access_token: string;
    refresh_token: string;
}
```

### Vamos criar uma interface para o usuário
```sh
$ ng g interface _interfaces/user

export interface User {
    token: string;
    id: number;
    id_company: number;
    name: string;
    email: string;
    active: string;
    created_at: Date;
    updated_at: Date;
    deleted_at: Date;
}
```

### Vamos criar o serviço que fará a autenticação do usuário
```sh
$ ng g s _services/auth --skipTests
```
##### auth.service.ts
```
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Observable } from 'rxjs';
import 'rxjs/add/operator/do';
import { Token } from '../_interfaces/token';
import { User } from '../_interfaces/user';
import { map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private http: HttpClient, private router: Router) { }

  login(formData): Observable<Token> {
    return this.http.post<Token>(environment.apiUrl + '/oauth/token', formData)
      .pipe(
        map(token => {
          if (token) {
            localStorage.setItem('currentToken', btoa(JSON.stringify(token)));
            return <Token>token;
          } else {
            return null;
          }

        })
      );
  }

  getCurrentUser(): Observable<User> {
    return this.http.get<User>(environment.apiUrl + '/api/user/me')
      .pipe(
        map(user => {
          if (user) {
            localStorage.setItem('currentUser', btoa(JSON.stringify(user)));
            return <User>user;
          } else {
            this.logout();
          }
        })
      )
  }

  logout(): void {
    this.http.get(environment.apiUrl + '/api/user/logout').subscribe(res =>{
      localStorage.removeItem('currentUser');
      localStorage.removeItem('currentToken');
      this.router.navigate(['login']);
    });
  }

  check(): boolean {
    return localStorage.getItem('currentToken') ? true : false;
  }

  getUser(): User {
    return localStorage.getItem('currentUser') ? JSON.parse(atob(localStorage.getItem('currentUser'))) : null;
  }

  getToken(): Token {
    return localStorage.getItem('currentToken') ? JSON.parse(atob(localStorage.getItem('currentToken'))) : null;
  }

  refreshToken(): Observable<Token> {
    let currentToken = this.getToken();
    let token = currentToken.access_token;

    return this.http.post<Token>(`${environment.apiUrl}/oauth/token/refresh`, { 'token': token })
      .pipe(
        map(data => {

          if (data && data.access_token) {
            const token = data;
            localStorage.setItem('currentToken', btoa(JSON.stringify(token)));
            return <Token>token;
          } else {
            return null;
          }

        }));
  }


  getAuthToken(): string {
    let currentToken = this.getToken();

    if (currentToken != null) {
      return currentToken.access_token;
    }

    return '';
  }

}
```

### Vamos criar o "auth.guard.ts"
Ele que protegerá as rotas privadas.
1. Clique com o botão direito na pasta __app__ e new folder "_guards";
2. Dentro da pasta _guards crie o arquivo __auth.guard.ts__ e insira o código abaixo:
```
import { Observable } from 'rxjs';
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router, CanActivateChild } from '@angular/router';
import { AuthService } from './../_services/auth.service';

@Injectable()
export class AuthGuard implements CanActivate, CanActivateChild {

  constructor(private auth: AuthService, private router: Router) { }

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
    if ( this.auth.check() ) {
      return true;
    }
    this.router.navigate(['login'], { queryParams: { returnUrl: state.url }});
  }
  
  canActivateChild(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
    if ( this.auth.check() ) {
      return true;
    }
    this.router.navigate(['login'], { queryParams: { returnUrl: state.url }});
  }

}
```

### Vamos criar o "interceptor"
Ele que interceptará as requisições ao servidor para inserir no cabeçalho da requisição o token do usuário autenticado.
1. Clique com o botão direito na pasta __app__ e new folder "_interceptors";
2. Dentro da pasta _interceptors crie o arquivo __token.interceptor.ts__ e insira o código abaixo:

```
import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpErrorResponse, HttpSentEvent, HttpHeaderResponse, HttpProgressEvent, HttpResponse, HttpUserEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { AuthService } from '../_services/auth.service';
import { BehaviorSubject, throwError } from 'rxjs';
import { catchError, map, finalize, switchMap, take, filter } from 'rxjs/operators';
import { User } from '../_interfaces/user';
import { Router } from '@angular/router';
import { Token } from '../_interfaces/token';

/** Pass untouched request through to the next request handler. */
@Injectable()
export class TokenInterceptor implements HttpInterceptor {

  constructor(private authService: AuthService, private router: Router) { }
 
  isRefreshingToken: boolean = false;
  tokenSubject: BehaviorSubject<string> = new BehaviorSubject<string>(null);
 
  intercept(request: HttpRequest<any>, next: HttpHandler) : Observable<HttpSentEvent | HttpHeaderResponse | HttpProgressEvent | HttpResponse<any> | HttpUserEvent<any> | any> {
    
    const requestUrl: Array<any> = request.url.split('/');
    const apiUrl: Array<any> = environment.apiUrl.split('/');
    const token = this.authService.getAuthToken();
    
    /* verifica se a requisição é para a api da aplicação */
    if (token && (requestUrl[2] === apiUrl[2])) {
    
      return next.handle(this.addTokenToRequest(request, token))
      .pipe(
        catchError(err => {
          if (err instanceof HttpErrorResponse) {
            switch ((<HttpErrorResponse>err).status) {
              case 401:
                return this.handle401Error(request, next);
              case 400:
                return <any>this.authService.logout();
              case 500:
                this.router.navigate(['error/internal-serve-error']);
              default:
                return throwError(err);
            }
          } else {
            return throwError(err);
          }
        }));  
      
    } else {

      return next.handle(request);

    }
 
    
  }
 
  private addTokenToRequest(request: HttpRequest<any>, token: string) : HttpRequest<any> {
    return request.clone({ setHeaders: { Authorization: `Bearer ${token}`}});
  }
 
  private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if(!this.isRefreshingToken) {
      this.isRefreshingToken = true;
 
      // Reset here so that the following requests wait until the token
      // comes back from the refreshToken call.
      this.tokenSubject.next(null);
      return this.authService.refreshToken()
        .pipe(
          switchMap((token: Token) => {
            if(token) {
              this.tokenSubject.next(token.access_token);;
              localStorage.setItem('currentToken', btoa(JSON.stringify(token)));
              return next.handle(this.addTokenToRequest(request, token.access_token));
            }
 
            return <any>this.authService.logout();
          }),
          catchError(err => {
            return <any>this.authService.logout();
          }),
          finalize(() => {
            this.isRefreshingToken = false;
          })
        );
    } else {
      this.isRefreshingToken = false;
 
      return this.tokenSubject
        .pipe(filter(token => token != null),
          take(1),
          switchMap(token => {
          return next.handle(this.addTokenToRequest(request, token));
        }));
    }
  }

}
```

Se der erro na importação ```import { Observable } from 'rxjs/Observable';``` rode no terminal:
```sh
$ npm install rxjs-compat
```

### Agora vamos criar o componente Dashboard que terá sua rota protegida
```sh
$ ng g c dashboard --skipTests
```

Vamos criar manualmente o __module__ e __route__ independentes para o component __dashboard__:
1. botão direito na pasta dashboard e new file __dashbord.module.ts__;
```
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { DashboardRoutes } from './dashboard.routing';
import { DashboardComponent } from './dashboard.component';

@NgModule({
  imports: [
    FormsModule,
    ReactiveFormsModule,
    CommonModule,
    RouterModule.forChild(DashboardRoutes)
  ],
  declarations: [
    DashboardComponent
  ]
})
export class DashboardModule { }
```

2. botão direito na pasta dashboard e new file __dasboard.routing.ts__;
```
import { Routes } from '@angular/router';
import { DashboardComponent } from './dashboard.component';

export const DashboardRoutes: Routes = [
    {
        path: '',
        children: [
            {
                path: '',
                component: DashboardComponent,
                data: {
                    title: 'Dashboard',
                    urls: [
                        { title: 'Dashboard', url: '/' },
                        { title: 'Dashboard' }
                    ]
                }
            }
        ]
    }

];
```

#### Vamos incluir a rota protegida dá seção dashboard no nosso arquivo de rotas principal "app.routing.ts"
```
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { FullComponent } from './layouts/full/full.component';
import { BlankComponent } from './layouts/blank/blank.component';
import { AuthGuard } from './_guards/auth.guard';

export const AppRoutingModule: Routes = [
  {
    path: '',
    component: FullComponent,
    canActivate: [AuthGuard],
    canActivateChild: [AuthGuard],
    children: [
      {
        path: '',
        redirectTo: '/dashboard',
        pathMatch: 'full'
      },
      {
        path: 'dashboard',
        loadChildren: './dashboard/dashboard.module#DashboardModule',
      }
    ]
  },
  {
    path: '',
    component: BlankComponent,
    children: [
      {
        path: 'login',
        loadChildren: './login/login.module#LoginModule',
      },
      {
        path: 'error',
        loadChildren: './error/error.module#ErrorModule',
      },
    ]
  },
  {
    path: '**',
    redirectTo: '/error/not-found'
  }
];
```

#### Vamos importar no app.module.ts o serviço de autenticação, o guard e o interceptor
```
import { BrowserModule } from '@angular/platform-browser';
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';

import { FormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { RouterModule } from '@angular/router';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

import { SpinnerComponent } from './shared/spinner.component';
import { BlankComponent } from './layouts/blank/blank.component';
import { FullComponent } from './layouts/full/full.component';
import { HeaderNavigationComponent } from './shared/header-navigation/header-navigation.component';

import { TokenInterceptor } from './_interceptors/token.interceptor';
import { AuthService } from './_services/auth.service';
import { AuthGuard } from './_guards/auth.guard';

@NgModule({
  declarations: [
    AppComponent,
    SpinnerComponent,
    BlankComponent,
    FullComponent,
    HeaderNavigationComponent,
  ],
  imports: [
    CommonModule,
    BrowserModule,
    FormsModule,
    HttpClientModule,
    RouterModule.forRoot(AppRoutingModule, { useHash: false }),
  ],
  providers: [
    AuthGuard,
    AuthService,
    { 
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptor,
      multi: true
    },
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

Agora restart o servidor
```sh
$ Ctrl + c
$ ng serve
```

Tente acessar a rota: [http://localhost:4200/dashboard](http://localhost:4200/dashboard), o __guard__ deverá redirecionar para tela de login.

### Finalizar o header com os dados do usuário logado
##### header-navigation.component.html
app/shared/header-navigation
```
<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Controle de Acesso</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent"
        aria-controls="navbarSupportedContent" aria-label="Toggle navigation" [attr.aria-expanded]="!isCollapsed"
        (click)="isCollapsed = !isCollapsed">
        <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navbarSupportedContent" [ngClass]="{'show': !isCollapsed}">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item active">
                <a class="nav-link" href="#">Link One</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#">Link Two</a>
            </li>
        </ul>
    </div>
</nav>
```

##### header-navigation.component.ts
app/shared/header-navigation
```
export class HeaderNavigationComponent implements OnInit {

  isCollapsed: boolean = true;

  constructor() { }

  ngOnInit() {
  }

  toggleCollapse(): void {
    this.isCollapsed = !this.isCollapsed;
  }

}
```

##### header-navigation.component.scss
app/shared/header-navigation
```
.bg-light {
    background-color: #d6d6d6 !important;
}
```

### Incluindo o AlertifyJS
[Link para Documentação](https://alertifyjs.com/)
```sh
$ npm install alertifyjs --save
```
Incluir a chamada para o __js__ e __css__ no __angular.json__
```
 "styles": [
    "src/assets/scss/style.scss",
    "./node_modules/alertifyjs/build/css/alertify.min.css",
],
"scripts": [
    "./node_modules/alertifyjs/build/alertify.min.js"
]
```

Criar um serviço para o __AlertifyJS__
```sh
$ ng g s _services/Alertify --skipTests
```
##### alertify.service.js
```
import { Injectable } from '@angular/core';
import alertify from 'alertifyjs';

@Injectable({
  providedIn: 'root'
})
export class AlertifyService {

  constructor() {
    alertify.defaults = {
      // dialogs defaults
      autoReset:true,
      basic:false,
      closable:true,
      closableByDimmer:true,
      frameless:false,
      maintainFocus:true, // <== global default not per instance, applies to all dialogs
      maximizable:true,
      modal:true,
      movable:true,
      moveBounded:false,
      overflow:true,
      padding: true,
      pinnable:true,
      pinned:true,
      preventBodyShift:false, // <== global default not per instance, applies to all dialogs
      resizable:true,
      startMaximized:false,
      transition:'pulse',

      // notifier defaults
      notifier:{
          // auto-dismiss wait time (in seconds)  
          delay:5,
          // default position
          position:'bottom-right',
          // adds a close button to notifier messages
          closeButton: false
      },

      // language resources 
      glossary:{
          // dialogs default title
          title:'AlertifyJS',
          // ok button text
          ok: 'Ok',
          // cancel button text
          cancel: 'Cancelar'            
      },

      // theme settings
      theme:{
          // class name attached to prompt dialog input textbox.
          // input:'ajs-input',
          // class name attached to ok button
          // ok:'ajs-ok',
          // class name attached to cancel button 
          // cancel:'ajs-cancel'
          
          ok: "btn btn-info",
          cancel: "btn btn-danger",
          input: "form-control"
      }
    };
  }

  confirm(title: string, message: string, onok: () => any, oncancel: () => any) {
    alertify.defaults.glossary.ok = 'Sim';
    alertify.defaults.glossary.cancel = 'Não';
    alertify.confirm(`<h4>${title}</h4>`, message, onok, oncancel);
  }

  success(message: string) {
    alertify.success(message);
  }

  error(message: string) {
    alertify.error(message);
  }

  warning(message: string) {
    alertify.warning(message);
  }

  message(message: string) {
    alertify.message(message);
  }

  alert(title: string, message: string, onok: () => any) {
    alertify.alert(`<h4>${title}</h4>`, message, onok);
  }
}
```

##### Usando o Alertify em um componente:
```
import { AlertifyService } from '../../_services/alertify.service';

export class MyComponent implements OnInit {

  constructor(
    private alertify: AlertifyService,
  ) {}
  
    btnDelete() {
        this.alertify.confirm('Atenção', 'Deseja excluir o registro?',
            () => {
                this.alertify.success('Excluído!');
            },
            () => {
                this.alertify.error('Cancelado!');
            }
        );
    }
}
```

#### instalar angular-fontawesome
```sh
$ npm install @fortawesome/fontawesome-svg-core
$ npm install @fortawesome/free-solid-svg-icons
# Veja a tabela de compatibilidade abaixo para escolher a versão correta
$ npm install @fortawesome/angular-fontawesome@<version>
```

##### Tabela de compatibilidade
@fortawesome/angular-fontawesome | Angular
---|---
0.1.x | 5.x
0.2.x | 6.x
0.3.x | 6.x && 7.x
0.4.x | 8.x

##### Como usar
1. Inclua FontAwesomeModule no imports do ```src/app/app.module.ts```
_OBS.: se você estiver usando módulos por componente importe no módulo do componente_
```
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';

@NgModule({
  imports: [
    BrowserModule,
    FontAwesomeModule
  ],
  declarations: [AppComponent],
  bootstrap: [AppComponent]
})
export class AppModule { }
```
2. Import os ícones que for utilizar no seu componente ```src/app/app.component.ts```
```
import { Component } from '@angular/core';
import { faCoffee } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent {
  faCoffee = faCoffee;
}
```
3. Insira o ícone no seu html ```src/app/app.component.html```:
```
<fa-icon [icon]="faCoffee"></fa-icon>
```

### Utiulizando BREADCRUMBS

##### Criar um componente na pasta shared
```sh
$ ng g c shared/breadcrumbs --skipTests
```
Editar ```breadcrumbs.component.ts```
```
import { Component, Input, OnInit } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { Router, NavigationEnd, ActivatedRoute } from '@angular/router';
import { filter, map, mergeMap } from 'rxjs/operators';

@Component({
  selector: 'app-breadcrumbs',
  templateUrl: './breadcrumbs.component.html',
  styleUrls: ['./breadcrumbs.component.scss']
})
export class BreadcrumbsComponent implements OnInit {

  @Input() layout;
  pageInfo;
  constructor(
    private router: Router,
    private activatedRoute: ActivatedRoute,
    private titleService: Title
  ) {
    this.router.events
      .pipe(filter(event => event instanceof NavigationEnd))
      .pipe(map(() => this.activatedRoute))
      .pipe(
        map(route => {
          while (route.firstChild) {
            route = route.firstChild;
          }
          return route;
        })
      )
      .pipe(filter(route => route.outlet === 'primary'))
      .pipe(mergeMap(route => route.data))
      .subscribe(event => {
        this.titleService.setTitle(event['title']);
        this.pageInfo = event;
      });
  }
  
  ngOnInit() {}

}
```

Editar o ```breadcrumbs.component.html```
```
<!-- ============================================================== -->
<!-- Bread crumb and right sidebar toggle -->
<!-- ============================================================== -->
<div class="page-breadcrumb">
    <div class="row">
        <div class="col-12 align-self-center">
            <h4 class="page-title">{{pageInfo?.title}}</h4>
            <div class="d-flex align-items-center">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <ng-template ngFor let-url [ngForOf]="pageInfo?.urls" let-last="last">
                            <li class="breadcrumb-item" *ngIf="!last" [routerLink]="url.url">
                                <a href='javascript:void(0)'>{{url.title}}</a>
                            </li>
                            <li class="breadcrumb-item active" *ngIf="last">{{url.title}}</li>
                        </ng-template>
                    </ol>
                </nav>
            </div>
        </div>
    </div>
</div>
<!-- ============================================================== -->
<!-- End Bread crumb and right sidebar toggle -->
<!-- ============================================================== -->
```

Incluir a tag do breadcrumbs no layout **full** abaixo do header
```
<app-breadcrumbs></app-breadcrumbs>
```