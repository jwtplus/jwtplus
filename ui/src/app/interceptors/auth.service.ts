import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // If the request has the custom header, skip adding Authorization
    if (req.headers.has('X-Skip-Auth')) {
      const clonedReq = req.clone({ headers: req.headers.delete('X-Skip-Auth') });
      return next.handle(clonedReq);
    }

    // Apply Authorization header
    const authToken = sessionStorage.getItem('key') as string;
    const clonedReq = req.clone({
      setHeaders: { Authorization: authToken }
    });

    return next.handle(clonedReq);
  }
}
