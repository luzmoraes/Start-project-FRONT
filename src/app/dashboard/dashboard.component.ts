import { Component, OnInit } from '@angular/core';
import { AlertifyService } from '../_services/alertify.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {

  constructor(private alertify: AlertifyService) { }

  ngOnInit() {
  }
  
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
