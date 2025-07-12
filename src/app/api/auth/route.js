import { NextResponse } from 'next/server';
import { Security, DatabaseHardening, InputHardening } from '@/lib/security';
import crypto from 'crypto';

const SECURITY_CONFIG = {
  maxRequestSize: 1024 * 1024, // 1MB max
  allowedOrigins: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://192.168.1.100:3000'],
  suspiciousPatterns: [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /eval\s*\(/gi,
    /Function\s*\(/gi
  ]
};

async function validateRequest(request) {
  const violations = [];
  
  const contentLength = parseInt(request.headers.get('content-length') || '0');
  if (contentLength > SECURITY_CONFIG.maxRequestSize) {
    violations.push('REQUEST_TOO_LARGE');
  }
  
  const contentType = request.headers.get('content-type');
  if (!contentType || !contentType.includes('application/json')) {
    violations.push('INVALID_CONTENT_TYPE');
  }
  
  const origin = request.headers.get('origin');
  if (origin && !SECURITY_CONFIG.allowedOrigins.includes(origin)) {
    violations.push('INVALID_ORIGIN');
  }
  
  const userAgent = request.headers.get('user-agent') || '';
  const suspiciousUAPatterns = [
    /curl/i, /wget/i, /python/i, /bot/i, /crawler/i, /spider/i
  ];
  
  if (process.env.NODE_ENV === 'production') {
    const isSuspiciousUA = suspiciousUAPatterns.some(pattern => pattern.test(userAgent));
    if (isSuspiciousUA || userAgent.length < 10) {
      violations.push('SUSPICIOUS_USER_AGENT');
    }
  }
  
  const requiredHeaders = ['user-agent', 'accept'];
  for (const header of requiredHeaders) {
    if (!request.headers.get(header)) {
      violations.push(`MISSING_HEADER_${header.toUpperCase()}`);
    }
  }
  
  return violations;
}

function deepSanitizeInput(obj, path = '') {
  if (typeof obj !== 'object' || obj === null) {
    if (typeof obj === 'string') {
      for (const pattern of SECURITY_CONFIG.suspiciousPatterns) {
        if (pattern.test(obj)) {
          throw new Error(`Malicious content detected at ${path}: ${pattern.source}`);
        }
      }
      
      return obj
        .trim()
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .substring(0, 1000);
    }
    return obj;
  }
  
  const sanitized = Array.isArray(obj) ? [] : {};
  
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    
    if (typeof key === 'string' && /[<>{}()]/g.test(key)) {
      throw new Error(`Invalid key name: ${key}`);
    }
    
    sanitized[key] = deepSanitizeInput(value, currentPath);
  }
  
  return sanitized;
}

async function detectAttackPatterns(request, body, clientIP) {
  const threats = [];
  
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b.*\b(FROM|INTO|SET|WHERE|EXEC)\b)/i,
    /(OR|AND)\s+\d+\s*=\s*\d+/i,
    /'\s*(OR|AND)\s*'.*'=/i,
    /UNION\s+SELECT/i,
    /;\s*DROP\s+TABLE/i
  ];
  
  const requestString = JSON.stringify(body).toLowerCase();
  for (const pattern of sqlPatterns) {
    if (pattern.test(requestString)) {
      threats.push({
        type: 'SQL_INJECTION_ATTEMPT',
        pattern: pattern.source,
        severity: 'HIGH'
      });
    }
  }
  
  const noSqlPatterns = [
    /\$where/i,
    /\$ne.*null/i,
    /\$regex/i,
    /\$gt.*0/i
  ];
  
  for (const pattern of noSqlPatterns) {
    if (pattern.test(requestString)) {
      threats.push({
        type: 'NOSQL_INJECTION_ATTEMPT',
        pattern: pattern.source,
        severity: 'HIGH'
      });
    }
  }
  
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /expression\s*\(/gi
  ];
  
  for (const pattern of xssPatterns) {
    if (pattern.test(requestString)) {
      threats.push({
        type: 'XSS_ATTEMPT',
        pattern: pattern.source,
        severity: 'MEDIUM'
      });
    }
  }
  
  const cmdPatterns = [
    /[;&|`$()]/g,
    /\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)\b/i
  ];
  
  for (const pattern of cmdPatterns) {
    if (pattern.test(requestString)) {
      threats.push({
        type: 'COMMAND_INJECTION_ATTEMPT',
        pattern: pattern.source,
        severity: 'HIGH'
      });
    }
  }
  
  if (!Security.checkRateLimit(`attack_detect_${clientIP}`, 10, 60000)) {
    threats.push({
      type: 'FREQUENCY_ATTACK',
      severity: 'HIGH'
    });
  }
  
  return threats;
}

export async function POST(request) {
  const startTime = Date.now();
  let clientIP = 'unknown';
  let requestId = crypto.randomBytes(8).toString('hex');
  
  try {
    const validationErrors = await validateRequest(request);
    if (validationErrors.length > 0) {
      await Security.logSecurityEvent(null, 'REQUEST_VALIDATION_FAILED', request, {
        violations: validationErrors,
        requestId
      });
      
      return NextResponse.json(
        { error: 'Request validation failed', requestId },
        { status: 400 }
      );
    }
    
    clientIP = Security.getClientIP(request);
    let body;

    try {
      const rawBody = await request.text();
      
      if (!rawBody.trim()) {
        return NextResponse.json(
          { error: 'Request body required', requestId },
          { status: 400 }
        );
      }
      
      body = JSON.parse(rawBody);
      body = deepSanitizeInput(body);
      
    } catch (error) {
      await Security.logSecurityEvent(null, 'INVALID_JSON_REQUEST', request, {
        error: error.message,
        requestId
      });
      
      return NextResponse.json(
        { error: 'Invalid JSON format', requestId },
        { status: 400 }
      );
    }
    
    const threats = await detectAttackPatterns(request, body, clientIP);
    if (threats.length > 0) {
      await Security.logSecurityEvent(null, 'SECURITY_THREATS_DETECTED', request, {
        threats,
        requestId,
        clientIP
      });
      
      const highSeverityThreats = threats.filter(t => t.severity === 'HIGH');
      if (highSeverityThreats.length > 0) {
        return NextResponse.json(
          { error: 'Security violation detected', requestId },
          { status: 403 }
        );
      }
    }
    
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action') || body.action;

    if (!action || !['login', 'register', 'logout', 'verify'].includes(action)) {
      return NextResponse.json(
        { error: 'Invalid or missing action parameter', requestId },
        { status: 400 }
      );
    }

    const rateLimitKey = `auth_${action}_${clientIP}`;
    const rateLimits = {
      login: { attempts: 5, window: 300000 },    // 5 intentos en 5 minutos
      register: { attempts: 3, window: 600000 }, // 3 intentos en 10 minutos
      logout: { attempts: 10, window: 60000 },   // 10 intentos en 1 minuto
      verify: { attempts: 20, window: 60000 }    // 20 intentos en 1 minuto
    };
    
    const limit = rateLimits[action];
    if (!Security.checkRateLimit(rateLimitKey, limit.attempts, limit.window)) {
      await Security.logSecurityEvent(null, 'RATE_LIMIT_EXCEEDED', request, {
        action,
        clientIP,
        requestId
      });
      
      return NextResponse.json(
        { error: 'Rate limit exceeded. Please try again later.', requestId },
        { status: 429 }
      );
    }

    let result;
    switch (action) {
      case 'login':
        result = await handleSecureLogin(request, body, requestId);
        break;
      case 'register':
        result = await handleSecureRegister(request, body, requestId);
        break;
      case 'logout':
        result = await handleSecureLogout(request, body, requestId);
        break;
      case 'verify':
        result = await handleSecureVerify(request, body, requestId);
        break;
    }
    
    await Security.logSecurityEvent(result.userId || null, 'AUTH_ACTION_SUCCESS', request, {
      action,
      requestId,
      processingTime: Date.now() - startTime
    });
    
    return NextResponse.json({
      ...result,
      requestId,
      processingTime: Date.now() - startTime
    });

  } catch (error) {
    await Security.logSecurityEvent(null, 'AUTH_CRITICAL_ERROR', request, {
      error: error.message,
      stack: error.stack?.substring(0, 500),
      requestId,
      clientIP
    });
        
    return NextResponse.json(
      { 
        error: 'Internal server error',
        requestId,
        ...(process.env.NODE_ENV === 'development' && { details: error.message })
      },
      { status: 500 }
    );
  }
}

async function handleSecureLogin(request, body, requestId) {
  const { username, password } = body;

  if (!username || !password) {
    throw new Error('Username and password are required');
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('Username and password must be strings');
  }

  if (username.length < 3 || username.length > 50) {
    throw new Error('Username must be between 3 and 50 characters');
  }

  if (password.length < 6 || password.length > 128) {
    throw new Error('Password must be between 6 and 128 characters');
  }

  let sanitizedUsername;
  try {
    const result = InputHardening.validateInputUltraSecure(username, 'string', { maxLength: 50 });
    sanitizedUsername = result.sanitized;
  } catch (error) {
    throw new Error('Invalid username format');
  }

  const clientIP = Security.getClientIP(request);

  if (await Security.isAccountLocked(sanitizedUsername)) {
    await Security.logSecurityEvent(null, 'LOGIN_ATTEMPT_LOCKED_ACCOUNT', request, { 
      username: sanitizedUsername,
      requestId
    });
    throw new Error('Account temporarily locked due to failed attempts');
  }

  const queryObj = {
    query: `
      SELECT id, username, email, password_hash, salt, is_active, daily_calorie_goal 
      FROM users 
      WHERE (username = ? OR email = ?) AND is_active = 1
    `,
    params: [sanitizedUsername, sanitizedUsername]
  };

  const users = await Promise.race([
    DatabaseHardening.executeSecureQuery(queryObj),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Database timeout')), 5000)
    )
  ]);

  const user = users[0];

  if (!user) {
    await Security.logSecurityEvent(null, 'LOGIN_FAILED', request, { 
      username: sanitizedUsername,
      requestId,
      reason: 'user_not_found'
    });
    throw new Error('Invalid credentials');
  }

  const isPasswordValid = await Security.verifyPassword(password, user.password_hash, user.salt);

  if (!isPasswordValid) {
    await Security.incrementFailedAttempts(sanitizedUsername);
    await Security.logSecurityEvent(user.id, 'LOGIN_FAILED', request, { 
      username: sanitizedUsername,
      requestId,
      reason: 'invalid_password'
    });
    throw new Error('Invalid credentials');
  }

  await Security.resetFailedAttempts(user.id);

  if (!user.password_hash.startsWith('$2')) {
    await Security.migratePasswordToBcrypt(user.id, password);
  }

  const sessionToken = Security.generateRandomToken(64);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  const insertQuery = DatabaseHardening.createSecureQuery();
  const insertObj = insertQuery.insert('user_sessions', {
    user_id: user.id,
    session_token: sessionToken,
    expires_at: expiresAt,
    ip_address: clientIP,
    user_agent: request.headers.get('user-agent') || 'unknown'
  });

  await DatabaseHardening.executeSecureQuery(insertObj);

  await Security.logSecurityEvent(user.id, 'LOGIN_SUCCESS', request, { 
    username: sanitizedUsername,
    requestId
  });

  return {
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      daily_calorie_goal: user.daily_calorie_goal || 2000
    },
    session_token: sessionToken,
    expires_at: expiresAt.toISOString(),
    userId: user.id
  };
}

async function handleSecureRegister(request, body, requestId) {
  const { username, email, password } = body;

  if (!username || !email || !password) {
    throw new Error('All fields are required');
  }

  if (typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
    throw new Error('All fields must be strings');
  }

  let sanitizedUsername, sanitizedEmail;
  
  try {
    const usernameResult = InputHardening.validateInputUltraSecure(username, 'username');
    sanitizedUsername = usernameResult.sanitized;
  } catch (error) {
    throw new Error('Username validation failed: ' + error.message.replace('Input validation failed: ', ''));
  }

  try {
    const emailResult = InputHardening.validateInputUltraSecure(email, 'email');
    sanitizedEmail = emailResult.sanitized;
  } catch (error) {
    throw new Error('Email validation failed: ' + error.message.replace('Input validation failed: ', ''));
  }

  try {
    InputHardening.validateInputUltraSecure(password, 'password');
  } catch (error) {
    const passwordErrors = error.message.replace('Input validation failed: ', '');
    throw new Error(passwordErrors);
  }

  const clientIP = Security.getClientIP(request);
  if (!Security.checkRateLimit(`register_${clientIP}`, 2, 600000)) {
    throw new Error('Too many registration attempts. Please try later.');
  }

  const checkQuery = {
    query: `SELECT id FROM users WHERE username = ? OR email = ?`,
    params: [sanitizedUsername, sanitizedEmail]
  };

  const existingUsers = await DatabaseHardening.executeSecureQuery(checkQuery);

  if (existingUsers.length > 0) {
    await Security.logSecurityEvent(null, 'REGISTER_ATTEMPT_DUPLICATE', request, { 
      username: sanitizedUsername, 
      email: sanitizedEmail,
      requestId
    });
    throw new Error('Username or email already exists');
  }

  const { hash, salt } = await Security.hashPassword(password);
  const insertQuery = DatabaseHardening.createSecureQuery();

  const insertObj = insertQuery.insert('users', {
    username: sanitizedUsername,
    email: sanitizedEmail,
    password_hash: hash,
    salt: salt
  });

  const result = await DatabaseHardening.executeSecureQuery(insertObj);
  const userId = result.insertId;

  await Security.logSecurityEvent(userId, 'USER_REGISTERED', request, { 
    username: sanitizedUsername,
    email: sanitizedEmail,
    requestId
  });

  return {
    success: true,
    message: 'User registered successfully',
    user_id: userId,
    userId
  };
}

async function handleSecureLogout(request, body, requestId) {
  const { session_token } = body;

  if (!session_token || typeof session_token !== 'string') {
    throw new Error('Session token is required');
  }

  if (session_token.length < 32) {
    throw new Error('Invalid session token format');
  }

  const selectQuery = {
    query: `SELECT user_id FROM user_sessions WHERE session_token = ? AND is_active = 1`,
    params: [session_token]
  };

  const sessions = await DatabaseHardening.executeSecureQuery(selectQuery);

  const updateQuery = {
    query: `UPDATE user_sessions SET is_active = 0 WHERE session_token = ?`,
    params: [session_token]
  };

  await DatabaseHardening.executeSecureQuery(updateQuery);

  if (sessions[0]) {
    await Security.logSecurityEvent(sessions[0].user_id, 'LOGOUT_SUCCESS', request, {
      requestId
    });
  }

  return { 
    success: true,
    message: 'Logged out successfully',
    userId: sessions[0]?.user_id 
  };
}

async function handleSecureVerify(request, body, requestId) {
  const { session_token } = body;

  if (!session_token || typeof session_token !== 'string') {
    throw new Error('Session token is required');
  }

  if (session_token.length < 32) {
    throw new Error('Invalid session token format');
  }

  const queryObj = {
    query: `
      SELECT us.user_id, us.expires_at, u.username, u.email, u.daily_calorie_goal
      FROM user_sessions us
      JOIN users u ON us.user_id = u.id
      WHERE us.session_token = ? AND us.is_active = 1 AND us.expires_at > NOW()
    `,
    params: [session_token]
  };

  const sessions = await DatabaseHardening.executeSecureQuery(queryObj);
  const session = sessions[0];

  if (!session) {
    throw new Error('Invalid or expired session');
  }

  await Security.logSecurityEvent(session.user_id, 'SESSION_VERIFIED', request, {
    requestId
  });

  return {
    success: true,
    user: {
      id: session.user_id,
      username: session.username,
      email: session.email,
      daily_calorie_goal: session.daily_calorie_goal || 2000
    },
    userId: session.user_id
  };
}

export async function GET() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function PUT() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function DELETE() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}