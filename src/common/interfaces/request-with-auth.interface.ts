import { Request } from 'express';

export interface RequestWithAuth extends Request {
  user: {
    id: number;
  };
  cookies: {
    access_token: string;
    refresh_token: string;
  };
}
