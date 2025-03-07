import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

const routes: Routes = [
  { path: 'login', loadChildren: () => import('./login/login.module').then(m => m.LoginModule) },
  { path: 'app-home', loadChildren: () => import('./app-home/app-home.module').then(m => m.AppHomeModule) },
  { path: 'root-home', loadChildren: () => import('./root-home/root-home.module').then(m => m.RootHomeModule) },
  { path: '', loadChildren: () => import('./login/login.module').then(m => m.LoginModule) },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
