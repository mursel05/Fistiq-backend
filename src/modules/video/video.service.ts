import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { spawn } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { QualityProfile } from './interfaces/quality-profile.interface';

const DEFAULT_QUALITY_PROFILES: QualityProfile[] = [
  {
    name: '360p',
    scale: '640:360',
    videoBitrate: '800k',
    audioBitrate: '128k',
  },
  {
    name: '720p',
    scale: '1280:720',
    videoBitrate: '2800k',
    audioBitrate: '128k',
  },
  {
    name: '1080p',
    scale: '1920:1080',
    videoBitrate: '5000k',
    audioBitrate: '128k',
  },
];

@Injectable()
export class VideoService {
  private readonly logger = new Logger(VideoService.name);
  private readonly baseOutputDir: string;
  private readonly defaultKeyServUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.baseOutputDir = this.configService.get<string>(
      'TRANSCODE_OUTPUT_DIR',
      './streams',
    );
    this.defaultKeyServUrl = this.configService.get<string>(
      'HLS_KEY_SERVE_URL',
      'https://PLACEHOLDER/key',
    );
  }

  async transcodeVideo(inputFile: string, videoId: string) {
    const outputDir = this.baseOutputDir;
    const keyServUrl = this.defaultKeyServUrl;
    const qualities = DEFAULT_QUALITY_PROFILES;

    const outDir = path.join(outputDir, videoId);
    this.ensureDir(outDir);

    const { keyPath, keyinfoPath } = this.writeEncryptionKey(
      outDir,
      keyServUrl,
    );

    this.logger.log(`Starting multi-quality encode — videoId: ${videoId}`);
    this.logger.log(`Input  : ${inputFile}`);
    this.logger.log(`Output : ${outDir}`);

    const durationSec = await this.probeDuration(inputFile);
    const completedQualities: string[] = [];

    for (const quality of qualities) {
      this.logger.log(`Encoding ${quality.name}...`);
      try {
        await this.transcodeQuality(
          inputFile,
          outDir,
          quality,
          keyinfoPath,
          durationSec,
        );
        completedQualities.push(quality.name);
        this.logger.log(`✓ ${quality.name} complete`);
      } catch (err) {
        this.logger.error(
          `✗ ${quality.name} failed: ${(err as Error).message}`,
        );
        throw err;
      }
    }

    this.createMasterPlaylist(outDir, qualities);
    this.logger.log('All qualities encoded successfully');

    return {
      videoId,
      qualities: completedQualities,
      keyPath,
      outputDir: outDir,
    };
  }

  private transcodeQuality(
    inputFile: string,
    outDir: string,
    quality: QualityProfile,
    keyinfoPath: string,
    durationSec: number,
  ): Promise<void> {
    const chunksDir = path.join(outDir, `chunks_${quality.name}`);
    const outputPlaylist = path.join(outDir, `${quality.name}.m3u8`);
    const segmentPattern = path.join(chunksDir, 'seg%03d.ts');

    this.ensureDir(chunksDir);

    const args = this.buildFfmpegArgs(
      inputFile,
      quality,
      keyinfoPath,
      segmentPattern,
      outputPlaylist,
    );

    return this.runFfmpeg(args, quality.name, durationSec);
  }

  /**
   * Build the ffmpeg CLI argument array for a single quality encode.
   */
  private buildFfmpegArgs(
    inputFile: string,
    quality: QualityProfile,
    keyinfoPath: string,
    segmentPattern: string,
    outputPlaylist: string,
  ): string[] {
    const [width, height] = quality.scale.split(':');

    return [
      '-i',
      inputFile,

      '-c:v',
      'libx264',
      '-b:v',
      quality.videoBitrate,
      '-vf',
      `scale=${width}:${height}`,
      '-r',
      '30',

      '-c:a',
      'aac',
      '-b:a',
      quality.audioBitrate,

      '-hls_time',
      '4',
      '-hls_list_size',
      '0',
      '-hls_key_info_file',
      keyinfoPath,
      '-hls_segment_filename',
      segmentPattern,
      '-hls_flags',
      'independent_segments',
      '-f',
      'hls',

      outputPlaylist,
    ];
  }

  private runFfmpeg(
    args: string[],
    label: string,
    durationSec: number,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const proc = spawn('ffmpeg', args, {
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let lastPct = -1;

      proc.stderr.on('data', (chunk: Buffer) => {
        for (const line of chunk.toString().split('\n')) {
          const pct = this.parseProgressPercent(line, durationSec);
          if (pct !== null && pct !== lastPct) {
            lastPct = pct;
            process.stdout.write(`\r  [${label}] ${pct}%   `);
          }
        }
      });

      proc.on('close', (code: number) => {
        process.stdout.write('\n');
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`ffmpeg exited with code ${code} for "${label}"`));
        }
      });

      proc.on('error', (err: NodeJS.ErrnoException) => {
        process.stdout.write('\n');
        if (err.code === 'ENOENT') {
          reject(
            new Error(
              'ffmpeg binary not found. Install it and ensure it is in your PATH.',
            ),
          );
        } else {
          reject(err);
        }
      });
    });
  }

  private createMasterPlaylist(
    outDir: string,
    qualities: QualityProfile[],
  ): void {
    const lines: string[] = ['#EXTM3U', '#EXT-X-VERSION:3', ''];

    for (const q of qualities) {
      const [width, height] = q.scale.split(':');
      const bandwidth = parseInt(q.videoBitrate, 10) * 1000; // '2800k' → 2800000

      lines.push(
        `#EXT-X-STREAM-INF:BANDWIDTH=${bandwidth},RESOLUTION=${width}x${height}`,
      );
      lines.push(`${q.name}.m3u8`);
      lines.push('');
    }

    const masterPath = path.join(outDir, 'master.m3u8');
    fs.writeFileSync(masterPath, lines.join('\n'));
    this.logger.log(`Master playlist written → ${masterPath}`);
  }

  private writeEncryptionKey(outDir: string, keyServUrl: string) {
    const encKey = crypto.randomBytes(16);
    const keyPath = path.join(outDir, 'enc.key');
    const keyinfoPath = path.join(outDir, 'hls.keyinfo');

    fs.writeFileSync(keyPath, encKey);
    fs.writeFileSync(keyinfoPath, [keyServUrl, keyPath, ''].join('\n'));

    return { keyPath, keyinfoPath };
  }

  private probeDuration(inputFile: string): Promise<number> {
    return new Promise((resolve) => {
      const args = [
        '-v',
        'error',
        '-show_entries',
        'format=duration',
        '-of',
        'default=noprint_wrappers=1:nokey=1',
        inputFile,
      ];

      const proc = spawn('ffprobe', args);
      let output = '';

      proc.stdout.on('data', (d: Buffer) => {
        output += d.toString();
      });
      proc.on('close', () => {
        const secs = parseFloat(output.trim());
        resolve(isNaN(secs) ? 0 : secs);
      });
      proc.on('error', () => resolve(0));
    });
  }

  /**
   * Parse ffmpeg stderr to extract a percent-complete value.
   * ffmpeg emits `time=HH:MM:SS.xx` lines during encoding.
   */
  private parseProgressPercent(
    line: string,
    durationSec: number,
  ): number | null {
    if (!durationSec || durationSec <= 0) return null;
    const match = line.match(/time=(\d{2}):(\d{2}):(\d{2}\.\d+)/);
    if (!match) return null;
    const elapsed = +match[1] * 3600 + +match[2] * 60 + parseFloat(match[3]);
    return Math.min(100, Math.round((elapsed / durationSec) * 100));
  }

  // ─── Private: Filesystem ─────────────────────────────────────────────────────

  /** Ensure a directory exists, creating it recursively if needed. */
  private ensureDir(dir: string): void {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}
