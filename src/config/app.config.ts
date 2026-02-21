import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  nodeEnv: process.env.NODE_ENV,
  port: process.env.PORT,
  apiPrefix: process.env.API_PREFIX,
  clientUrl: process.env.CLIENT_URL,
  baseUrl: process.env.BASE_URL,
  cookieSecret: process.env.COOKIE_SECRET,
  cookieDomain: process.env.COOKIE_DOMAIN,
  cookiePath: process.env.COOKIE_PATH,
}));
