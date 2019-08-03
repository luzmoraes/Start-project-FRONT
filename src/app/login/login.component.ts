import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, FormControl, Validators } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { environment } from '../../environments/environment';

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
    private router: Router
  ) { }

  onSubmitLogin() {
    console.log('loading...');
  }

  ngOnInit() {
  }


}