import { Mutation, Resolver } from '@nestjs/graphql';
import { Video } from './entities/video.entity';
import { VideoService } from './video.service';
import { UploadedFile } from '@nestjs/common';

@Resolver(() => Video)
export class VideoResolver {
  constructor(private readonly videoService: VideoService) {}

  @Mutation(() => Video)
  async uploadVideo(@UploadedFile() file: Express.Multer.File) {
    const videoId = `video-${Date.now()}`;
    const inputFile = file.path;
    return this.videoService.transcodeVideo(inputFile, videoId);
  }
}
