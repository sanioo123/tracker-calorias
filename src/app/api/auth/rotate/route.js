import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { Security } from '@/lib/security';

export async function POST(request) {
  try {
    const user = await Security.authenticateRequest(request);
    
    const body = await request.json();
    const { current_token, device_fingerprint } = body;

    const [currentSession] = await query(`
      SELECT session_token, created_at, ip_address 
      FROM user_sessions 
      WHERE user_id = ? AND session_token = ? AND is_active = 1
    `, [user.id, current_token]);

    if (!currentSession) {
      return NextResponse.json(
        { error: 'Token actual inválido' },
        { status: 401 }
      );
    }

    const timeSinceCreation = Date.now() - new Date(currentSession.created_at).getTime();
    if (timeSinceCreation < 300000) { // 5 minutos
      return NextResponse.json(
        { error: 'Token rotado recientemente, espera antes de rotar nuevamente' },
        { status: 429 }
      );
    }

    const clientIP = Security.getClientIP(request);
    if (!Security.checkRateLimit(`token_rotation_${user.id}`, 6, 3600000)) { // 6 por hora
      await Security.logSecurityEvent(user.id, 'TOKEN_ROTATION_RATE_LIMIT', request, {
        ip: clientIP,
        device_fingerprint
      });
      return NextResponse.json(
        { error: 'Demasiadas rotaciones de token. Intenta más tarde' },
        { status: 429 }
      );
    }

    const newSessionToken = Security.generateRandomToken(64);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

    await query(`
      UPDATE user_sessions 
      SET session_token = ?, expires_at = ?, created_at = NOW()
      WHERE user_id = ? AND session_token = ?
    `, [newSessionToken, expiresAt, user.id, current_token]);

    setTimeout(async () => {
      await query(`
        UPDATE user_sessions 
        SET is_active = 0 
        WHERE session_token = ? AND user_id = ?
      `, [current_token, user.id]);
    }, 30000);

    await Security.logSecurityEvent(user.id, 'TOKEN_ROTATED', request, {
      old_token_preview: current_token.substring(0, 8) + '...',
      new_token_preview: newSessionToken.substring(0, 8) + '...',
      device_fingerprint
    });

    return NextResponse.json({
      success: true,
      session_token: newSessionToken,
      expires_at: expiresAt.toISOString(),
      message: 'Token rotado exitosamente'
    });

  } catch (error) {
    console.error('Token rotation error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al rotar token' },
      { status: 500 }
    );
  }
}