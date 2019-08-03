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