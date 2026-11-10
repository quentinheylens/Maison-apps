"""Authenticated GET-only API with paging, bounded work and data-free audit."""
import json
import uuid
from datetime import datetime, timezone
from diagnostic_real import VERSION
from diagnostic_real.files import ConfigError
from diagnostic_real.source import allowed
from gateway.real_source import SourceUnavailable
from gateway.service import GatewayError, RateLimiter, require_query_keys, one, bounded_limit

ROUTES = {'/v2/capabilities', '/v2/entities', '/v2/registry', '/v2/definitions', '/v2/history',
          '/v2/traces', '/v2/code-links', '/v2/unavailable'}

class DiagnosticService:
    def __init__(self, source, audit):
        self.source, self.audit = source, audit
        self.rate = RateLimiter(30)

    def handle(self, method, path, query, identity):
        request = str(uuid.uuid4())
        status, outcome = 500, 'internal_error'
        try:
            if method != 'GET': raise GatewayError(405, 'method_not_allowed')
            if path == '/healthz':
                require_query_keys(query, set())
                status, outcome = 200, 'healthy'
                return 200, {'status': 'ok', 'version': VERSION, 'writes_enabled': False}
            if identity != 'codex-cloud': raise GatewayError(401, 'unauthorized')
            if not self.rate.allow(identity): raise GatewayError(429, 'rate_limited')
            if path not in ROUTES: raise GatewayError(404, 'not_found')
            data = self.read(path, query)
            response = {'request_id': request, 'observed_at': datetime.now(timezone.utc).isoformat(), 'data': data}
            if len(json.dumps(response, ensure_ascii=False, allow_nan=False).encode()) > 1024*1024:
                raise GatewayError(413, 'reduce_page_size')
            status, outcome = 200, 'allowed'
            return status, response
        except GatewayError as exc:
            status, outcome = exc.status, exc.code
        except (ValueError, TypeError): status, outcome = 400, 'invalid_request'
        except (SourceUnavailable, ConfigError): status, outcome = 503, 'read_capability_unavailable'
        except Exception: status, outcome = 503, 'read_unavailable'
        finally:
            self.audit.write(request_id=request, identity=identity, method=method if method in {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'} else 'OTHER',
                             route=path if path in ROUTES or path == '/healthz' else '/unmatched', status=status, outcome=outcome)
        return status, {'request_id': request, 'error': {'code': outcome}}

    def page(self, items, query, **extra):
        limit = bounded_limit(query, 200, default=100)
        offset = int(one(query, 'offset', required=False) or '0')
        if not 0 <= offset <= 20000: raise ValueError('invalid_offset')
        return {'items': items[offset:offset+limit], 'count': len(items),
                'next_offset': offset+limit if offset+limit < len(items) else None, **extra}

    def read(self, path, query):
        if path == '/v2/capabilities':
            require_query_keys(query, set())
            return {'version': VERSION, 'real_read': True, 'writes_enabled': False,
                    'routes': sorted(ROUTES), 'history_max_hours': 24, 'cache_seconds': 30,
                    'configuration': 'sanitized read-only projections; not deployable files',
                    'traces': 'Core permissions and stored trace retention required; failures return 503',
                    'logs': 'raw logs excluded; errors from stored traces only'}
        if path in {'/v2/entities', '/v2/unavailable'}:
            require_query_keys(query, {'limit','offset','domain','entity_id'})
            items = self.source.states()
            domain = one(query, 'domain', required=False)
            entity = one(query, 'entity_id', required=False)
            if domain: items = [x for x in items if x['entity_id'].split('.')[0] == domain]
            if entity:
                if not allowed(entity): raise ValueError('invalid_entity')
                items = [x for x in items if x['entity_id'] == entity]
            if path.endswith('/unavailable'): items = [x for x in items if x['state'] in {'unknown','unavailable'}]
            return self.page(items, query)
        if path == '/v2/registry':
            require_query_keys(query, {'kind','limit','offset'})
            kind = one(query, 'kind')
            if kind not in {'entities','devices','areas'}: raise ValueError('invalid_registry')
            return self.page(self.source.registry(kind), query)
        if path == '/v2/definitions':
            require_query_keys(query, {'limit','offset','revision'})
            data = self.source.definitions()
            revision = one(query, 'revision', required=False)
            if revision and revision != data['revision']: raise GatewayError(409, 'snapshot_changed')
            return self.page(data['files'], query, revision=data['revision'],
                             read_only_projection=True, limitations=data['limitations'], excluded=data['excluded'])
        if path == '/v2/history':
            require_query_keys(query, {'entity_id','start','end','limit'})
            return self.source.history(one(query,'entity_id'), one(query,'start'), one(query,'end'), bounded_limit(query,1000))
        if path == '/v2/traces':
            require_query_keys(query, {'domain','item_id','run_id'})
            return self.source.traces(one(query,'domain'),one(query,'item_id'),one(query,'run_id',required=False))
        if path == '/v2/code-links':
            require_query_keys(query, {'limit','offset','entity_id'})
            links = self.source.links()
            entity = one(query,'entity_id',required=False)
            items = links['objects']
            if entity:
                if not allowed(entity): raise ValueError('invalid_entity')
                items = [x for x in items if entity in x['entity_references']]
            return self.page(items, query, revision=links['revision'], limitations=links['limitations'])
        raise GatewayError(404,'not_found')
