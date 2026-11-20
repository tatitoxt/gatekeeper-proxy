import { matchRoute, stripHopByHop } from '../../src/core/proxy.js';
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
