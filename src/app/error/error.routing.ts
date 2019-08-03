import { Routes } from '@angular/router';
import { NotFoundComponent } from './not-found/not-found.component';
import { InternalServeErrorComponent } from './internal-serve-error/internal-serve-error.component';

export const ErrorRoutes: Routes = [
    {
        path: '',
        children: [
            {
                path: 'not-found',
                component: NotFoundComponent
            },
            {
                path: 'internal-serve-error',
                component: InternalServeErrorComponent
            }
        ]
    }

];