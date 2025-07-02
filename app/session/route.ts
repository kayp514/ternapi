import { type NextRequest, NextResponse } from 'next/server';
import { cookies, headers } from 'next/headers';
import { createSessionCookie } from '../../utils/sessionTernSecure';
import { setCorsHeaders } from '../../utils/cors';

export async function POST(request: NextRequest) {
    try {
        // Parse request body with error handling
        let body;
        try {
            body = await request.json();
        } catch (parseError) {
            console.error('Error parsing request body:', parseError);
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'Invalid JSON in request body' }, { status: 400 }),
                request
            );
        }

        const { idToken, csrfToken } = body;
        
        // Get CSRF token with error handling
        let cookieCsrfToken;
        try {
            cookieCsrfToken = request.cookies.get('__session_terncf');
            console.log('Cookie CSRF Token:', cookieCsrfToken);
        } catch (cookieError) {
            console.error('Error getting CSRF cookie:', cookieError);
        }

        // Validate required fields
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

        // Get origin with error handling
        let origin;
        try {
            origin = request.headers.get('origin');
        } catch (headerError) {
            console.error('Error getting origin header:', headerError);
            origin = undefined;
        }

        // Create session cookie with error handling
        let result;
        try {
            result = await createSessionCookie(idToken, origin || undefined);
            console.log('Session creation result:', result);
        } catch (sessionError) {
            console.error('Error creating session cookie:', sessionError);
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'Failed to create session' }, { status: 500 }),
                request
            );
        }

        if (result.success) {
            try {
                // Build cookie value
                let cookieValue = `__session_cookie=${result.sessionCookie}; Max-Age=${Math.floor(result.expiresIn! / 1000)}; HttpOnly; Path=/; SameSite=None`;
                
                if (process.env.NODE_ENV === 'production') {
                    cookieValue += '; Secure';
                }
                
                //if (result.cookieDomain) {
                //    cookieValue += `; Domain=${result.cookieDomain}`;
                //}
                
                // Create response
                const response = NextResponse.json({ success: true, message: result.message }, { status: 200 });
                console.log('Response', response);
                
                // Set cookie header
                try {
                    response.headers.set('Set-Cookie', cookieValue);
                } catch (cookieSetError) {
                    console.error('Error setting cookie header:', cookieSetError);
                    return setCorsHeaders(
                        NextResponse.json({ success: false, message: 'Failed to set session cookie' }, { status: 500 }),
                        request
                    );
                }
                
                return setCorsHeaders(response, request);
            } catch (responseError) {
                console.error('Error creating success response:', responseError);
                return setCorsHeaders(
                    NextResponse.json({ success: false, message: 'Failed to create response' }, { status: 500 }),
                    request
                );
            }
        } else {
            try {
                return setCorsHeaders(
                    NextResponse.json({ success: false, message: result.message }, { status: 401 }),
                    request
                );
            } catch (errorResponseError) {
                console.error('Error creating error response:', errorResponseError);
                return NextResponse.json({ success: false, message: 'Internal server error' }, { status: 500 });
            }
        }

    } catch (error) {
        console.error('Unexpected error in session POST route:', error);
        
        // Handle different types of errors
        if (error instanceof SyntaxError) {
            try {
                return setCorsHeaders(
                    NextResponse.json({ success: false, message: 'Invalid JSON in request body' }, { status: 400 }),
                    request
                );
            } catch (corsError) {
                console.error('Error setting CORS headers for syntax error:', corsError);
                return NextResponse.json({ success: false, message: 'Invalid JSON in request body' }, { status: 400 });
            }
        }

        // Generic error response
        try {
            return setCorsHeaders(
                NextResponse.json({ success: false, message: 'Internal server error' }, { status: 500 }),
                request
            );
        } catch (corsError) {
            console.error('Error setting CORS headers for generic error:', corsError);
            return NextResponse.json({ success: false, message: 'Internal server error' }, { status: 500 });
        }
    }
}

export async function OPTIONS(request: NextRequest) {
    try {
        const allowedOrigins = ['https://ternauth-test.vercel.app', 'http://localhost:3000', 'https://dev-vogat-v1.vercel.app'];
        
        let origin;
        try {
            origin = request.headers.get('origin');
        } catch (headerError) {
            console.error('Error getting origin header in OPTIONS:', headerError);
            origin = null;
        }

        const response = new NextResponse(null, { 
            status: 204,
            headers: {
                'Access-Control-Allow-Origin': origin && allowedOrigins.includes(origin) ? origin : 'https://ternauth-test.vercel.app',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '86400'
            }
        });
        return response;
    } catch (error) {
        console.error('Error in OPTIONS method:', error);
        return new NextResponse(null, { status: 500 });
    }
}