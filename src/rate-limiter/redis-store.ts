import { createClient, type RedisClientType } from 'redis';
import { logger } from '../utils/logger.js';
import type { RateLimitResult, RateLimitStore, RateLimitWindow } from './store.js';

/**
 * Atomically trim, check and commit a hit across the route and global windows
 * (sorted sets scored by request timestamp). Both windows are evaluated in one
 * script so a rejected request never consumes quota in either window.
 *
 * Returns: [allowed (0|1), scope, limit, remaining, resetMs]
 */
const CHECK_LUA = `
local now = tonumber(ARGV[1])
local member = ARGV[2]
local routeKey = KEYS[1]
local globalKey = KEYS[2]
local routeWindow = tonumber(ARGV[3])
local routeMax = tonumber(ARGV[4])
local globalWindow = tonumber(ARGV[5])
local globalMax = tonumber(ARGV[6])

local function reset_ms(key, windowMs)
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  if oldest[2] then
    local reset = oldest[2] + windowMs - now
    if reset < 0 then return 0 end
    return reset
  end
  return 0
end

redis.call('ZREMRANGEBYSCORE', globalKey, '-inf', now - globalWindow)
local gCount = redis.call('ZCARD', globalKey)

local rRemaining = -1
if routeKey ~= '' then
  redis.call('ZREMRANGEBYSCORE', routeKey, '-inf', now - routeWindow)
  local rCount = redis.call('ZCARD', routeKey)
  if rCount >= routeMax then
    return {0, 'route', routeMax, 0, reset_ms(routeKey, routeWindow)}
  end
  rRemaining = routeMax - rCount - 1
end
if gCount >= globalMax then
  return {0, 'global', globalMax, 0, reset_ms(globalKey, globalWindow)}
end

if routeKey ~= '' then
  redis.call('ZADD', routeKey, now, member)
  redis.call('PEXPIRE', routeKey, routeWindow + 1000)
end
redis.call('ZADD', globalKey, now, member)
redis.call('PEXPIRE', globalKey, globalWindow + 1000)

local gRemaining = globalMax - gCount - 1
if routeKey ~= '' and rRemaining < gRemaining then
  return {1, 'route', routeMax, rRemaining, 0}
end
return {1, 'global', globalMax, gRemaining, 0}
`;

/**
 * Redis-backed store (sorted sets + Lua, one EVAL per check) so multiple
 * Gatekeeper instances share the same rate-limit budget. Members are
 * `now:seq` to keep hits unique within a millisecond.
 */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly client: RedisClientType;
  private readonly prefix: string;
  private seq = 0;

  constructor(url: string, keyPrefix = 'gk:rl:') {
    this.prefix = keyPrefix;
    this.client = createClient({ url });
    this.client.on('error', (err) => logger.warn({ err: String(err) }, 'rate-limit redis error'));
    // Commands issued before CONNECT resolves queue offline; do not await here.
    this.client.connect().catch((err) =>
      logger.error({ err: String(err) }, 'rate-limit redis connect failed')
    );
  }

  public async check(
    clientIp: string,
    route: (RateLimitWindow & { key: string }) | null,
    global: RateLimitWindow,
    now: number
  ): Promise<RateLimitResult> {
    const routeKey = route ? `${this.prefix}r:${route.key}:${clientIp}` : '';
    const globalKey = `${this.prefix}g:${clientIp}`;
    const member = `${now}:${this.seq++}`;
    const raw = (await this.client.eval(CHECK_LUA, {
      keys: [routeKey, globalKey],
      arguments: [
        String(now),
        member,
        String(route?.windowMs ?? 0),
        String(route?.maxRequests ?? 0),
        String(global.windowMs),
        String(global.maxRequests)
      ]
    })) as [number, string, number, number, number];
    return {
      allowed: raw[0] === 1,
      scope: raw[1] as RateLimitResult['scope'],
      limit: raw[2],
      remaining: raw[3],
      resetMs: raw[4]
    };
  }

  /** Keys expire by TTL; nothing to sweep. */
  public sweep(): Promise<number> {
    return Promise.resolve(0);
  }

  public async trackedKeys(): Promise<number> {
    let count = 0;
    for await (const batch of this.client.scanIterator({ MATCH: `${this.prefix}*`, COUNT: 500 })) {
      // node-redis yields SCAN results as batches of keys
      count += Array.isArray(batch) ? batch.length : 1;
    }
    return count;
  }

  public async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.destroy();
    }
  }
}
