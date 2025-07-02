import { type NextRequest, NextResponse } from 'next/server';
import { cookies, headers } from 'next/headers';
import { createSessionCookie } from '../../utils/sessionTernSecure';
import { setCorsHeaders } from '../../utils/cors';


export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { idToken, csrfToken, origin } = body;
        console.log('Request Body:', body);
        
        //const cookieStore = await cookies();
        //const cookieCsrfToken = cookieStore.get('__session_terncf')?.value;
        const cookieCsrfToken = request.cookies.get('__session_terncf');
        console.log('Cookie CSRF Token:', cookieCsrfToken);

        if (!idToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'ID token is required' }, { status: 400 }), 
                request
            );
        }

        if (!csrfToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'CSRF token is required' }, { status: 400 }), 
                request
            );
        }

        //const origin = request.headers.get('origin');
        const result = await createSessionCookie(idToken, origin || undefined);

        if (result.success) {
            const response = NextResponse.json({ 
                success: true, 
                message: result.message,
                sessionToken: result.sessionCookie,
                expiresIn: result.expiresIn
            }, { status: 200 });
            console.log('Response', response);
            return setCorsHeaders(response, request);
        } else {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: result.message }, { status: 401 })
            );
        }

    } catch (error) {
        console.error('Error in session POST route:', error);
        if (error instanceof SyntaxError) {
            return NextResponse.json(
                { success: false, message: 'Invalid JSON in request body' },
                { status: 400 }
            );
        }

        return NextResponse.json(
            { success: false, message: 'Internal server error' },
            { status: 500 }
        );
    }
}

export async function OPTIONS(request: NextRequest) {
  const allowedOrigins = ['https://ternauth-test.vercel.app', 'http://localhost:3000', 'http://localhost:3001', 'https://dev-vogat-v1.vercel.app'];
  const origin = request.headers.get('origin');

  const response = new NextResponse(null, { 
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin && allowedOrigins.includes(origin) ? origin: 'https://ternauth-test.vercel.app',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400'
    }
  });
  return response;
}
