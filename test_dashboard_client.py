import urllib.request
import json

api_key = 'sk-test-1234567890abcdef'

def req(path):
    r = urllib.request.Request(f'http://127.0.0.1:8766{path}')
    r.add_header('X-API-Key', api_key)
    return urllib.request.urlopen(r, timeout=5).read().decode()

print('=== /health ===')
print(req('/health'))
print()
print('=== /ready ===')
print(get_url('/api/v1/dashboard/ready'))
print()
print('=== /assets ===')
print(req('/api/v1/dashboard/assets'))
print()
print('=== /findings ===')
print(get_url('/api/v1/dashboard/findings'))
print()
print('=== /readiness ===')
print(get_url('/api/v1/dashboard/readiness'))
print()
print('=== /guard-events ===')
print(get_url('/api/v1/dashboard/guard-events'))