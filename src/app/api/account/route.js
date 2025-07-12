// app/api/account/route.js
import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { Security } from '@/lib/security';

export async function GET(request) {
  try {
    const user = await Security.authenticateRequest(request);
    
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action');

    switch (action) {
      case 'logs':
        return await handleGetLogs(user);
      case 'info':
      default:
        return await handleGetAccountInfo(user);
    }

  } catch (error) {
    console.error('Account GET error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al obtener información de la cuenta' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}

export async function POST(request) {
  try {
    const user = await Security.authenticateRequest(request);
    
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action');

    switch (action) {
      case 'password':
        return await handleChangePassword(request, user);
      default:
        return NextResponse.json(
          { error: 'Acción no válida para POST' },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('Account POST error:', error);
    return NextResponse.json(
      { error: error.message || 'Error en la operación' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}

async function handleGetAccountInfo(user) {
  const accounts = await query(`
    SELECT id, username, email, created_at, updated_at, daily_calorie_goal,
           failed_login_attempts, last_failed_login
    FROM users 
    WHERE id = ?
  `, [user.id]);

  const account = accounts[0];

  if (!account) {
    return NextResponse.json(
      { error: 'Cuenta no encontrada' },
      { status: 404 }
    );
  }

  return NextResponse.json({
    success: true,
    account: {
      id: account.id,
      username: account.username,
      email: account.email,
      created_at: account.created_at,
      updated_at: account.updated_at,
      daily_calorie_goal: account.daily_calorie_goal,
      failed_login_attempts: account.failed_login_attempts,
      last_failed_login: account.last_failed_login
    }
  });
}

async function handleGetLogs(user) {
  const logs = await query(`
    SELECT action, ip_address, user_agent, details, created_at
    FROM security_logs 
    WHERE user_id = ? 
    AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ORDER BY created_at DESC
    LIMIT 15
  `, [user.id]);

  return NextResponse.json({
    success: true,
    logs: logs.map(log => ({
      action: log.action,
      ip_address: log.ip_address,
      user_agent: log.user_agent,
      details: log.details ? JSON.parse(log.details) : null,
      created_at: log.created_at
    })),
    total: logs.length
  });
}

async function handleChangePassword(request, user) {
  const body = await request.json();
  const { current_password, new_password } = body;

  if (!current_password || !new_password) {
    return NextResponse.json(
      { error: 'Contraseña actual y nueva son requeridas' },
      { status: 400 }
    );
  }

  const passwordErrors = Security.validatePassword(new_password);
  if (passwordErrors.length > 0) {
    return NextResponse.json(
      { error: passwordErrors.join('. ') },
      { status: 400 }
    );
  }

  const users = await query(`
    SELECT password_hash, salt FROM users WHERE id = ?
  `, [user.id]);

  const currentUser = users[0];
  if (!currentUser) {
    return NextResponse.json(
      { error: 'Usuario no encontrado' },
      { status: 404 }
    );
  }

  const isCurrentPasswordValid = await Security.verifyPassword(
    current_password, 
    currentUser.password_hash, 
    currentUser.salt
  );

  if (!isCurrentPasswordValid) {
    await Security.logSecurityEvent(user.id, 'PASSWORD_CHANGE_FAILED', request, {
      reason: 'incorrect_current_password'
    });
    
    return NextResponse.json(
      { error: 'La contraseña actual es incorrecta' },
      { status: 401 }
    );
  }

  if (!Security.checkRateLimit(`password_change_${user.id}`, 3, 300000)) {
    return NextResponse.json(
      { error: 'Demasiados intentos de cambio de contraseña. Intenta más tarde' },
      { status: 429 }
    );
  }

  const { hash, salt } = await Security.hashPassword(new_password);

  await query(`
    UPDATE users 
    SET password_hash = ?, salt = ?, updated_at = NOW()
    WHERE id = ?
  `, [hash, salt, user.id]);

  const currentSessionToken = request.headers.get('authorization')?.substring(7);
  await query(`
    UPDATE user_sessions 
    SET is_active = 0 
    WHERE user_id = ? AND session_token != ?
  `, [user.id, currentSessionToken]);

  await Security.logSecurityEvent(user.id, 'PASSWORD_CHANGED', request, {
    invalidated_sessions: true
  });

  return NextResponse.json({
    success: true,
    message: 'Contraseña actualizada exitosamente. Otras sesiones han sido cerradas.'
  });
}