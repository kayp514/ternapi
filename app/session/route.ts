import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { createSessionCookie } from '../../utils/sessionTernSecure';
import { setCorsHeaders } from '../../utils/cors';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { idToken, csrfToken } = body;
        
        const cookieStore = await cookies();
        const cookieCsrfToken = cookieStore.get('__session_terncf')?.value;

        if (!idToken) {
            const response = NextResponse.json(
                { success: false, message: 'ID token is required' },
                { status: 400 }
            );
            return setCorsHeaders(response);
        }

        if (!csrfToken) {
            const response = NextResponse.json(
                { success: false, message: 'CSRF token is required' },
                { status: 400 }
            );
            return setCorsHeaders(response);
        }

        if (!cookieCsrfToken) {
            const response = NextResponse.json(
                { success: false, message: 'CSRF token not found in cookies' },
                { status: 403 }
            );
            return setCorsHeaders(response);
        }

        if (csrfToken !== cookieCsrfToken) {
            const response = NextResponse.json(
                { success: false, message: 'CSRF token mismatch' },
                { status: 403 }
            );
            return setCorsHeaders(response);
        }

        const result = await createSessionCookie(idToken);

        if (result.success) {
            const response = NextResponse.json(
                { success: true, message: result.message },
                { status: 200 }
            );
            return setCorsHeaders(response);
        } else {
            const response = NextResponse.json(
                { success: false, message: result.message },
                { status: 401 }
            );
            return setCorsHeaders(response);
        }

    } catch (error) {
        console.error('Error in session POST route:', error);
        if (error instanceof SyntaxError) {
            const response = NextResponse.json(
                { success: false, message: 'Invalid JSON in request body' },
                { status: 400 }
            );
            return setCorsHeaders(response);
        }

        const response = NextResponse.json(
            { success: false, message: 'Internal server error' },
            { status: 500 }
        );
        return setCorsHeaders(response);
    }
}

export async function OPTIONS(request: NextRequest) {
    const response = new NextResponse(null, { status: 200 });
    return setCorsHeaders(response);
}