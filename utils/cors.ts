import { NextRequest, NextResponse } from 'next/server';

// In-memory store for rate limiting
// TODO: replace with Redis.
const rateLimitStore = new Map<string, { count: number; timestamp: number }>();

const allowedOrigins = [
  'https://dev-vogat-v1.vercel.app',
  'https://ternauth-test.vercel.app',
  'http://localhost:3000',
  'http://localhost:3001'
];

export function setCorsHeaders(response: NextResponse, request?: NextRequest): NextResponse {
  let allowedOrigin = allowedOrigins[0]; // Default fallback
  
  if (request) {
    const origin = request.headers.get('origin');
    if (origin && allowedOrigins.includes(origin)) {
      allowedOrigin = origin;
    }
  }
  
  response.headers.set('Access-Control-Allow-Origin', allowedOrigin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours

  return response;
}

export function rateLimit(request: NextRequest, limit: number, windowMs: number): boolean {
  // Get client IP address from headers
  const forwardedFor = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const clientIp = forwardedFor?.split(',')[0] || realIp || 'unknown';
  
  const now = Date.now();
  const windowStart = now - windowMs;
  
  for (const [key, value] of rateLimitStore.entries()) {
    if (value.timestamp < windowStart) {
      rateLimitStore.delete(key);
    }
  }
  
  // Get current rate limit data for this IP
  const currentLimit = rateLimitStore.get(clientIp);
  
  if (!currentLimit) {
    rateLimitStore.set(clientIp, { count: 1, timestamp: now });
    return true;
  }
  
  if (currentLimit.timestamp < windowStart) {
    rateLimitStore.set(clientIp, { count: 1, timestamp: now });
    return true;
  }
  
  if (currentLimit.count >= limit) {
    return false;
  }
  
  rateLimitStore.set(clientIp, {
    count: currentLimit.count + 1,
    timestamp: currentLimit.timestamp
  });
  
  return true;
}


export function createErrorResponse(message: string, status: number): NextResponse {
  return NextResponse.json(
    { error: message },
    { 
      status,
      headers: {
        'Content-Type': 'application/json',
      }
    }
  );
}