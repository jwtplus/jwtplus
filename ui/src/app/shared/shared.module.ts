import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgTemplateOutlet } from '@angular/common';
import { NgbToastModule } from '@ng-bootstrap/ng-bootstrap';

import { ToasterComponent } from './toaster/toaster.component';


@NgModule({
  declarations: [
    ToasterComponent
  ],
  imports: [
    CommonModule,
    NgTemplateOutlet,
    NgbToastModule
  ],
  exports:[
    ToasterComponent
  ]
})
export class SharedModule { }
