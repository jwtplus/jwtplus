import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs/internal/Subscription';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';

import { AppService, KeyTestPayload } from '../app.service';
import { ToasterService } from '../shared/toaster/toaster.service';

@Component({
  selector: 'app-login',
  standalone: false,
  templateUrl: './login.component.html'
})
export class LoginComponent implements OnInit, OnDestroy{

  sub$: Subscription = new Subscription(); 
  formLogin = new FormGroup({
		loginType: new FormControl('app', {validators: [Validators.required]}),
		key: new FormControl('', {validators: [Validators.required]}),
    appId: new FormControl('', {validators: [Validators.required]}),
	})

  constructor(
    private service: AppService, 
    private router: Router,
    private toasterService: ToasterService
  ) {}

  ngOnInit(): void {
    this.sub$.add(
      this.formLogin.get('loginType')?.valueChanges.subscribe(val=>{
        if (val == 'app'){
          this.formLogin.get('appId')?.setValidators(Validators.required);
        }else {
          this.formLogin.get('appId')?.removeValidators(Validators.required);
        }
        this.formLogin.get('appId')?.updateValueAndValidity({ emitEvent: false });
      })
    )
  }

  ngOnDestroy(): void {
    this.sub$.unsubscribe();
  }

  doLogin() {
    let payload: KeyTestPayload = {
      loginType: this.formLogin.get('loginType')?.value as string,
      AppId: this.formLogin.get('appId')?.value as string,
      Key: this.formLogin.get('key')?.value as string,
    };

    this.service.testKey(payload).subscribe({
      next: ()=>{
        sessionStorage.setItem("loginType", payload.loginType);
        sessionStorage.setItem("appId", payload.AppId as string);
        sessionStorage.setItem("key", payload.Key);
        if(payload.loginType == 'root'){
          this.router.navigateByUrl("/root-home");
        }else {
          this.router.navigateByUrl("/app-home");
        }
      },
      error:()=>{
        this.toasterService.show("Provided key or app id is invalid.", "bg-danger text-light");
      }
    });
  }
}
