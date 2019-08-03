import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Observable } from 'rxjs';
import 'rxjs/add/operator/do';
import { User } from '../_interfaces/user';
import { map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private http: HttpClient, private router: Router) { }

  /* Verifica se o usuário tá autenticado */
  check(): boolean {
    return localStorage.getItem('currentUser') ? true : false;
  }

  /*
    Realiza a autenticação na api e se o usuário for autenticado:
    1. chama o método "formatUser(data)" que irá formatar os dados retornado para ser compatível com a interface do usuário;
    2. Salva os dados do usuário no Local Storage.
   */
  login(credentials: {email: string, password: string}): Observable<User> {
    return this.http.post<User>(environment.apiUrl + '/auth/login', credentials)
      .pipe(
        map(data => {
          if (data) {
            const user = this.formatedUser(data);
            localStorage.setItem('currentUser', btoa(JSON.stringify(user)));
            return <User>user;
          } else {
            return null;
          }

        })
      );
  }

  /* Remove os dados do usuário autenticado do Local Storage e redireciona para tela de Login */
  logout(): void {
    localStorage.removeItem('currentUser');
    this.router.navigate(['autenticacao/login']);
  }

  /* Pega os dados do usuário do Local Storage */
  getUser(): User {
    return localStorage.getItem('currentUser') ? JSON.parse(atob(localStorage.getItem('currentUser'))) : null;
  }

  /* Renova o token do usuário cado o mesmo tenha expirado */
  refreshToken() : Observable<User> {
    let currentUser = this.getUser();
    let token = currentUser.token;
 
    return this.http.post<User>(`${environment.apiUrl}/auth/refresh`, { 'token': token })
      .pipe(
        map(data => {
 
          if (data && data.token) {
            const user = this.formatedUser(data);
            localStorage.setItem('currentUser', btoa(JSON.stringify(user)));
            return <User>user;
          } else {
            return null;
          }
 
      }));
  }


  /* Retorna o token do usuário autenticado */
  getAuthToken() : string {
    let currentUser = this.getUser();
 
    if(currentUser != null) {
      return currentUser.token;
    }
 
    return '';
  }

  /* Formata os dados retornado no login de acordo com a interface do usuário (Interfaces/user.ts) */
  formatedUser(data) {
    return {
      token: data.token,
      id: data.user.id,
      name: data.user.name,
      email: data.user.email,
      active: data.user.active,
      created_at: data.user.created_at,
      updated_at: data.user.updated_at,
      deleted_at: data.user.deleted_at
    }
  }

}