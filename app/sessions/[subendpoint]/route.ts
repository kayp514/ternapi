import { NextRequest, NextResponse } from 'next/server';

import { setCorsHeaders } from '../../../utils/cors';
import {
  clearSessionCookie,
  createSessionCookie,
  verifyTernSessionCookie,
} from '../../../utils/sessionTernSecure';

type RouteContext = {
  params: Promise<{
    subendpoint: string;
  }>;
};

const SESSION_COOKIE_NAME = '_session_cookie';

function withCors(request: NextRequest, response: NextResponse): NextResponse {
  return setCorsHeaders(response, request);
}

function createJsonResponse(
  request: NextRequest,
  body: Record<string, unknown>,
  status = 200,
): NextResponse {
  return withCors(request, NextResponse.json(body, { status }));
}

async function handleCreateSession(request: NextRequest): Promise<NextResponse> {
  let payload: { idToken?: string; csrfToken?: string; origin?: string };

  try {
    payload = await request.json();
  } catch {
    return createJsonResponse(request, {
      success: false,
      message: 'Invalid JSON in request body',
    }, 400);
  }

  const { idToken, csrfToken, origin } = payload;
  if (!idToken) {
    return createJsonResponse(request, {
      success: false,
      message: 'ID token is required',
    }, 400);
  }

  if (!csrfToken) {
    return createJsonResponse(request, {
      success: false,
      message: 'CSRF token is required',
    }, 400);
  }

  const sessionResult = await createSessionCookie(idToken, origin ?? request.headers.get('origin') ?? undefined);

  if (!sessionResult.success || !sessionResult.sessionCookie) {
    return createJsonResponse(request, {
      success: false,
      message: sessionResult.message ?? 'Failed to create session',
    }, 401);
  }

  const response = NextResponse.json(
    {
      success: true,
      message: sessionResult.message,
      sessionToken: sessionResult.sessionCookie,
      expiresIn: sessionResult.expiresIn,
    },
    { status: 200 },
  );

  const maxAgeSeconds = sessionResult.expiresIn ? Math.floor(sessionResult.expiresIn / 1000) : undefined;

  response.cookies.set(SESSION_COOKIE_NAME, sessionResult.sessionCookie, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: maxAgeSeconds,
    domain: sessionResult.cookieDomain,
  });

  return withCors(request, response);
}

async function handleVerifySession(request: NextRequest): Promise<NextResponse> {
  const sessionCookie = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (!sessionCookie) {
    return createJsonResponse(request, {
      success: false,
      message: 'Session cookie not found',
    }, 401);
  }

  const verification = await verifyTernSessionCookie(sessionCookie);
  if (!verification.valid) {
    return createJsonResponse(request, {
      success: false,
      message: verification.error?.message ?? 'Invalid session',
    }, 401);
  }

  return createJsonResponse(request, {
    success: true,
    user: {
      uid: verification.uid,
      email: verification.email,
    },
    authTime: verification.authTime,
  });
}

async function handleRevokeSession(request: NextRequest): Promise<NextResponse> {
  const result = await clearSessionCookie();
  return createJsonResponse(request, {
    success: result.success,
    message: result.message,
  });
}

export async function OPTIONS(request: NextRequest): Promise<NextResponse> {
  return withCors(request, new NextResponse(null, { status: 204 }));
}

export async function GET(request: NextRequest, props: RouteContext): Promise<NextResponse> {
  const params = await props.params;
  if (params.subendpoint === 'verify') {
    return handleVerifySession(request);
  }

  return createJsonResponse(request, {
    success: false,
    message: 'Sub-endpoint not found',
  }, 404);
}

export async function POST(
  request: NextRequest,
  props: RouteContext,
): Promise<NextResponse> {
  const params = await props.params;
  switch (params.subendpoint) {
    case 'createsession':
      return handleCreateSession(request);
    case 'revoke':
      return handleRevokeSession(request);
    default:
      return createJsonResponse(request, {
        success: false,
        message: 'Sub-endpoint not found',
      }, 404);
  }
}
