import { Component, OnInit } from '@angular/core';
import { AlertifyService } from '../_services/alertify.service';
import { faCoffee } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {

  constructor(private alertify: AlertifyService) { }

  faCoffee = faCoffee;
  
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
