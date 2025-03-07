import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RootHomeComponent } from './root-home.component';

describe('RootHomeComponent', () => {
  let component: RootHomeComponent;
  let fixture: ComponentFixture<RootHomeComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [RootHomeComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RootHomeComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
