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
            const res = NextResponse.json(
                { success: false, message: 'ID token is required' },
                { status: 400 }
            );

            return res;
        }

        if (!csrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token is required' },
                { status: 400 }
            );
        }

        if (!cookieCsrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token not found in cookies' },
                { status: 403 }
            );
        }


        if (csrfToken !== cookieCsrfToken) {
            return NextResponse.json(
                { success: false, message: 'CSRF token mismatch' },
                { status: 403 }
            );
        }

        const result = await createSessionCookie(idToken);

        if (result.success) {
            return NextResponse.json(
                { success: true, message: result.message },
                { status: 200 }
            );
        } else {
            return NextResponse.json(
                { success: false, message: result.message },
                { status: 401 }
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
