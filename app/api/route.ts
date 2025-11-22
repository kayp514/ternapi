'use server'

import { type NextRequest, NextResponse } from 'next/server';

import { setCorsHeaders } from '@/utils/cors';

export async function GET(request: NextRequest): Promise<NextResponse> {
  const response = NextResponse.json({
    success: true,
    message: 'TernSecure API root',
  });

  return setCorsHeaders(response, request);
}

export async function OPTIONS(request: NextRequest): Promise<NextResponse> {
  return setCorsHeaders(new NextResponse(null, { status: 204 }), request);
}
