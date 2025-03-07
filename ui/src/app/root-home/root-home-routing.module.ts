import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { RootHomeComponent } from './root-home.component';

const routes: Routes = [{ path: '', component: RootHomeComponent }];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class RootHomeRoutingModule { }
