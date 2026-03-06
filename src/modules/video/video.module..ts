import { Module } from '@nestjs/common';
import { VideoResolver } from './video.resolver';
import { VideoService } from './video.service';
import { Video } from './entities/video.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [TypeOrmModule.forFeature([Video])],
  providers: [VideoService, VideoResolver],
  exports: [VideoService],
})
export class VideoModule {}
