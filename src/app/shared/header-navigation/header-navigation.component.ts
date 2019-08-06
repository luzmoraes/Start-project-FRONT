import { Component, OnInit } from '@angular/core';
import { AlertifyService } from 'src/app/_services/alertify.service';
import { AuthService } from 'src/app/_services/auth.service';

@Component({
  selector: 'app-header-navigation',
  templateUrl: './header-navigation.component.html',
  styleUrls: ['./header-navigation.component.scss']
})
export class HeaderNavigationComponent implements OnInit {

  isCollapsed: boolean = true;

  constructor(
    private alertify: AlertifyService,
    private authService: AuthService
  ) { }

  ngOnInit() {
  }

  toggleCollapse(): void {
    this.isCollapsed = !this.isCollapsed;
  }

  logout() {
    this.alertify.confirm('Atenção', 'Deseja sair do sistema?',
      () => { this.authService.logout(); },
      () => {}
    );
  }

}
