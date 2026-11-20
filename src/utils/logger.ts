import pino from 'pino';

const pretty = process.env.NODE_ENV !== 'production' && process.env.LOG_FORMAT !== 'json';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: pretty
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:yyyy-mm-dd HH:MM:ss',
          ignore: 'pid,hostname'
        }
      }
    : undefined
});
