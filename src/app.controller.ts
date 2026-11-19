import { Controller, Get } from '@nestjs/common';
import { Public } from './common/decorators';
import { AppService } from './app.service';

@Controller('health')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get()
  checkHealth() {
    return this.appService.checkHealth();
  }
}
