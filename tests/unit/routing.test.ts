import { matchRoute, normalizedRequestPath, stripHopByHop } from '../../src/core/proxy.js';
import { RouteConfig } from '../../src/config/config.js';

const routes: RouteConfig[] = [
  { pathPrefix: '/api', targets: ['http://a'] },
  { pathPrefix: '/api/v2', targets: ['http://b'] },
  { pathPrefix: '/static/', targets: ['http://c'] }
];

describe('matchRoute', () => {
  test.each([
    ['/api', '/api'],
    ['/api/users?x=1', '/api'],
    ['/api?x=1', '/api'],
    ['/api/v2/users', '/api/v2'],
    ['/api/v2', '/api/v2'],
    ['/api/v20', '/api'],
    ['/static/app.js', '/static/']
  ])('%s -> %s', (url, prefix) => {
    expect(matchRoute(routes, url)?.pathPrefix).toBe(prefix);
  });

  test.each(['/apiary', '/', '/static', '/other'])('%s has no route', (url) => {
    expect(matchRoute(routes, url)).toBeNull();
  });

  test('a "/" route is the catch-all fallback', () => {
    const withRoot = [...routes, { pathPrefix: '/', targets: ['http://root'] }];
    expect(matchRoute(withRoot, '/apiary')?.pathPrefix).toBe('/');
    expect(matchRoute(withRoot, '/api/x')?.pathPrefix).toBe('/api');
  });
});

describe('stripHopByHop', () => {
  test('removes standard hop-by-hop headers and those named in Connection', () => {
    expect(
      stripHopByHop({
        connection: 'keep-alive, x-secret-hop',
        'keep-alive': 'timeout=5',
        'transfer-encoding': 'chunked',
        upgrade: 'websocket',
        'proxy-authorization': 'Basic abc',
        'x-secret-hop': '1',
        'content-type': 'application/json',
        'x-request-id': 'abc'
      })
    ).toEqual({ 'content-type': 'application/json', 'x-request-id': 'abc' });
  });
});

describe('normalizedRequestPath', () => {
  test('resolves dot segments so a weaker route cannot be smuggled past a stricter one', () => {
    expect(normalizedRequestPath('/api/./admin?id=1')).toBe('/api/admin?id=1');
    expect(normalizedRequestPath('/api/../auth')).toBe('/auth');
    const routes = [
      { pathPrefix: '/api', targets: ['http://a:1'], waf: { blockSqlInjection: false } },
      { pathPrefix: '/api/admin', targets: ['http://a:1'], waf: { blockSqlInjection: true } }
    ] as never[];
    expect(matchRoute(routes, normalizedRequestPath('/api/./admin'))).toBe(routes[1]);
  });

  test('drops absolute and scheme-relative authorities, keeping only path and query', () => {
    expect(normalizedRequestPath('http://internal.evil:9/admin')).toBe('/admin');
    expect(normalizedRequestPath('//internal.evil:9/admin?x=1')).toBe('/admin?x=1');
  });

  test('falls back to the raw value only when URL parsing fails', () => {
    expect(normalizedRequestPath('http://[')).toBe('http://[');
    // A bare relative string parses as a path and gains a leading slash.
    expect(normalizedRequestPath('%%%')).toBe('/%%%');
  });
});
