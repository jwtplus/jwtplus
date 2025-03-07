import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { environment } from '../environments/environment';

export interface KeyTestPayload{
  loginType: string,
  AppId?: string,
  Key: string,
}

export interface AppDetails{
  id: string,
  name: string,
  description: string,
  token_expiry: number,
  token_notbefore: number,
  refresh_expiry: number,
  refresh_notbefore: number,
  key_type: string,
  algo: string,
  rotation_period: number,
  add_time: number,
  update_time: number,
  last_key_rotate: number
}

@Injectable({
  providedIn: 'root'
})
export class AppService {

  constructor(private http: HttpClient) { }

  testKey(payload: KeyTestPayload){
    let headers = new HttpHeaders();
    headers = headers.append('Authorization', payload.Key)
    headers = headers.append('X-Skip-Auth', "true")

    if (payload.loginType == 'root'){
      return this.http.get<AppDetails>(
        environment.APIENDPOINT + "/root/list",
        {headers}
      );
    }

    return this.http.get<AppDetails>(
      environment.APIENDPOINT + "/app/" + payload.AppId,
      {headers}
    );
  }

  getAllProjects(rootKey:string){
    return this.http.get<AppDetails>(
			environment.APIENDPOINT + "/root"
		);
  } 
}
