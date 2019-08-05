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