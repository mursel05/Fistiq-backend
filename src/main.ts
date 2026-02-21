import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';
import helmet from '@fastify/helmet';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyCookie from '@fastify/cookie';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  try {
    logger.log('Starting application...');
    const app = await NestFactory.create<NestFastifyApplication>(
      AppModule,
      new FastifyAdapter(),
      {
        logger: WinstonModule.createLogger({
          transports: [
            new winston.transports.File({
              filename: 'logs/error.log',
              level: 'error',
              format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json(),
              ),
            }),
            new winston.transports.File({
              filename: 'logs/warn.log',
              level: 'warn',
              format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json(),
              ),
            }),
            new winston.transports.File({
              filename: 'logs/combined.log',
              format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json(),
              ),
            }),
            new winston.transports.Console({
              format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.colorize(),
                winston.format.printf(
                  ({
                    timestamp,
                    level,
                    message,
                    context,
                  }: {
                    timestamp: string;
                    level: string;
                    message: string;
                    context?: string;
                  }) => {
                    return `${timestamp} [${context}] ${level}: ${message}`;
                  },
                ),
              ),
            }),
          ],
        }),
      },
    );
    const configService = app.get(ConfigService);

    await app.register(fastifyCookie, {
      secret: configService.get<string>('app.cookieSecret') as string,
    });
    app.setGlobalPrefix(configService.get<string>('app.apiPrefix') as string);
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, transform: true }),
    );
    app.enableCors({
      origin: configService.get<string>('app.clientUrl'),
      credentials: true,
    });

    await app.register(helmet, {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: [`'self'`, 'unpkg.com'],
          styleSrc: [
            `'self'`,
            `'unsafe-inline'`,
            'cdn.jsdelivr.net',
            'fonts.googleapis.com',
            'unpkg.com',
          ],
          fontSrc: [`'self'`, 'fonts.gstatic.com', 'data:'],
          imgSrc: [`'self'`, 'data:', 'cdn.jsdelivr.net'],
          scriptSrc: [
            `'self'`,
            `https: 'unsafe-inline'`,
            `cdn.jsdelivr.net`,
            `'unsafe-eval'`,
          ],
        },
      },
    });
    await app.listen(configService.get<number>('app.port') as number);

    logger.log('Application is ready to accept requests');
  } catch (error) {
    logger.error(
      'Failed to start application',
      error instanceof Error ? error.stack : String(error),
    );
    process.exit(1);
  }

  process.on('SIGTERM', () => {
    logger.log('SIGTERM signal received: closing HTTP server');
  });
  process.on('SIGINT', () => {
    logger.log('SIGINT signal received: closing HTTP server');
    process.exit(0);
  });
}
void bootstrap();
