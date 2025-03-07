import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ToasterService {
  toasts: { text: string; classname: string }[] = [];

  show(text: string, classname = 'bg-success text-light') {
    this.toasts.push({ text, classname });
    setTimeout(() => this.removeToast(text), 5000); // Auto dismiss
  }

  removeToast(text: string) {
    this.toasts = this.toasts.filter(toast => toast.text !== text);
  }
}
