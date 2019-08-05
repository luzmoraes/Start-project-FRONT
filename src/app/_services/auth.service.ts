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