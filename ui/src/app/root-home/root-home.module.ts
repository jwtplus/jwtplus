import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { RootHomeRoutingModule } from './root-home-routing.module';
import { RootHomeComponent } from './root-home.component';


@NgModule({
  declarations: [
    RootHomeComponent
  ],
  imports: [
    CommonModule,
    RootHomeRoutingModule
  ]
})
export class RootHomeModule { }
