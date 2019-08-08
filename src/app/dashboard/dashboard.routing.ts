import { Routes } from '@angular/router';
import { DashboardComponent } from './dashboard.component';

export const DashboardRoutes: Routes = [
    {
        path: '',
        children: [
            {
                path: '',
                component: DashboardComponent,
                data: {
                    title: 'Título dá página',
                    urls: [
                        { title: 'Dashboard', url: '/' },
                        { title: 'principal' }
                    ]
                }
            }
        ]
    }

];