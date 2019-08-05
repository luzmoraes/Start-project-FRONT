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