import { Component } from '@angular/core';
import { ToasterService } from './toaster.service';

@Component({
  selector: 'app-toaster',
  standalone: false,
  templateUrl: './toaster.component.html'
})

export class ToasterComponent {
  constructor(public toasterService: ToasterService) {}
}
