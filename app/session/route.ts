import { type NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { createSessionCookie } from '../../utils/sessionTernSecure';
import { setCorsHeaders } from '../../utils/cors';


export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { idToken, csrfToken } = body;
        
        //const cookieStore = await cookies();
        //const cookieCsrfToken = cookieStore.get('__session_terncf')?.value;
        const cookieCsrfToken = request.cookies.get('__session_terncf');

        if (!idToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'ID token is required' }, { status: 400 })
            );
        }

        if (!csrfToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'CSRF token is required' }, { status: 400 })
            );
        }

        if (!cookieCsrfToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'CSRF token not found in cookies' }, { status: 403 })
            );
        }

        if (csrfToken !== cookieCsrfToken) {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'CSRF token mismatch' }, { status: 403 })
            );
        }

        const result = await createSessionCookie(idToken);

        if (result.success) {
            return setCorsHeaders(
                NextResponse.json({ success: true, message: result.message }, { status: 200 })
            );
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
  const response = new NextResponse(null, { 
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': 'https://ternauth-test.vercel.app',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400'
    }
  });
  return response;
}
