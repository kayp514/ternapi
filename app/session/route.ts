import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { createSessionCookie } from '../../utils/sessionTernSecure';

// CORS headers
const corsHeaders = {
    'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
};

// Handle preflight OPTIONS request
export async function OPTIONS() {
    return new NextResponse(null, {
        status: 200,
        headers: corsHeaders,
    });
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { idToken, csrfToken } = body;
        
        const cookieStore = await cookies();
        const cookieCsrfToken = cookieStore.get('__session_terncf')?.value;

        if (!idToken) {
            return NextResponse.json(
                { success: false, message: 'ID token is required' },
                { 
                    status: 400,
                    headers: corsHeaders
                }
            );
        }

        if (!csrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token is required' },
                { 
                    status: 400,
                    headers: corsHeaders
                }
            );
        }

        if (!cookieCsrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token not found in cookies' },
                { 
                    status: 403,
                    headers: corsHeaders
                }
            );
        }


        if (csrfToken !== cookieCsrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token mismatch' },
                { 
                    status: 403,
                    headers: corsHeaders
                }
            );
        }

        const result = await createSessionCookie(idToken);

        if (result.success) {
            return NextResponse.json(
                { success: true, message: result.message },
                { 
                    status: 200,
                    headers: corsHeaders
                }
            );
        } else {
            return NextResponse.json(
                { success: false, message: result.message },
                { 
                    status: 401,
                    headers: corsHeaders
                }
            );
        }

    } catch (error) {
        console.error('Error in session POST route:', error);
        if (error instanceof SyntaxError) {
            return NextResponse.json(
                { success: false, message: 'Invalid JSON in request body' },
                { 
                    status: 400,
                    headers: corsHeaders
                }
            );
        }

        return NextResponse.json(
            { success: false, message: 'Internal server error' },
            { 
                status: 500,
                headers: corsHeaders
            }
        );
    }
}