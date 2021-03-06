import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { DashboardRoutes } from './dashboard.routing';
import { DashboardComponent } from './dashboard.component';

import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';

@NgModule({
  imports: [
    FormsModule,
    ReactiveFormsModule,
    CommonModule,
    RouterModule.forChild(DashboardRoutes),
    FontAwesomeModule
  ],
  declarations: [
    DashboardComponent
  ]
})
export class DashboardModule { }