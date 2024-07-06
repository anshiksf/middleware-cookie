import {Middleware, MiddlewareContext} from '@loopback/rest';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

export const tokenInterceptorMiddleware: Middleware = async (
  middlewareCtx: MiddlewareContext,
  next: Function,
) => {
  const {request} = middlewareCtx;
  console.log('Request: %s %s', request.method, request.originalUrl);

  try {
    const cookie = request.headers.cookie;

    if (cookie) {
      try {
        const userId = decryptCookie(cookie);
        const token = createJwt(userId);
        request.headers.authorization = `Bearer ${token}`;
      } catch (error) {
        console.error('Error processing cookie:', error);
      }
    }

    // Proceed with next middleware
    const result = await next();

    // Process response
    console.log(
      'Response received for %s %s',
      request.method,
      request.originalUrl,
    );

    return result;
  } catch (err) {
    // Catch errors from downstream middleware
    console.error(
      'Error received for %s %s',
      request.method,
      request.originalUrl,
    );
    throw err;
  }
};

function decryptCookie(cookie: string): string {
  const decipher = crypto.createDecipher('aes256', process.env.ENCRYPTION_KEY || 'defaultEncryptionKey');
  let decrypted = decipher.update(cookie, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function createJwt(userId: string): string {
  const payload = {id: userId};
  return jwt.sign(payload, process.env.JWT_SECRET || 'defaultJwtSecret', {expiresIn: '1h'});
}
