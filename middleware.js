import { NextResponse } from 'next/server';

const CRITICAL_PATTERNS_2025 = [
  /(\bunion\b.*\bselect\b)/i,
  /((\%27)|(\'))\s*(\bor\b|\band\b)\s*((\%27)|(\'))/i,
  /\b(sleep|benchmark|waitfor|pg_sleep)\s*\(/i,
  /;\s*(drop|create|alter|delete)\b/i,
  
  /\$where\s*:/i,
  /\$ne\s*:\s*null/i,
  /\$regex\s*:/i,
  
  /[;&|`$(){}]/g,
  /\b(rm|wget|curl|bash|sh|powershell|cmd)\b/i,
  
  /__schema|__type|__directive/i,
  
  /\{\{.*\}\}/,
  /\{%.*%\}/,
  
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi
];

function detectCriticalThreats(input) {
  if (!input || typeof input !== 'string') {
    return { detected: false, patterns: [] };
  }
  
  const normalizedInput = input.toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
  
  const detectedPatterns = [];
  
  for (const pattern of CRITICAL_PATTERNS_2025) {
    if (pattern.test(normalizedInput)) {
      detectedPatterns.push({
        pattern: pattern.source,
        match: normalizedInput.match(pattern)?.[0] || 'unknown'
      });
    }
  }
  
  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns,
    risk: detectedPatterns.length > 2 ? 'CRITICAL' : 
          detectedPatterns.length > 0 ? 'HIGH' : 'LOW'
  };
}

function analyzeRequestInputs(request) {
  const threats = [];
  const url = new URL(request.url);
  
  for (const [key, value] of url.searchParams.entries()) {
    const analysis = detectCriticalThreats(value);
    if (analysis.detected) {
      threats.push({
        source: 'query',
        parameter: key,
        value: value.substring(0, 100),
        analysis
      });
    }
  }
  
  const suspiciousHeaders = [
    'x-forwarded-for', 'referer', 'user-agent', 
    'x-original-url', 'x-rewrite-url', 'x-real-ip'
  ];
  
  suspiciousHeaders.forEach(headerName => {
    const headerValue = request.headers.get(headerName);
    if (headerValue) {
      const analysis = detectCriticalThreats(headerValue);
      if (analysis.detected) {
        threats.push({
          source: 'header',
          parameter: headerName,
          value: headerValue.substring(0, 100),
          analysis
        });
      }
    }
  });
  
  return threats;
}

function validateSecurityHeaders(request) {
  const violations = [];
  
  const contentType = request.headers.get('content-type');
  if (request.method === 'POST' && (!contentType || !contentType.includes('application/json'))) {
    violations.push('INVALID_CONTENT_TYPE');
  }
  
  if (process.env.NODE_ENV === 'production') {
    const userAgent = request.headers.get('user-agent') || '';
    const suspiciousUAPatterns = [
      /curl/i, /wget/i, /python/i, /bot/i, /crawler/i, /spider/i, /scanner/i
    ];
    
    if (suspiciousUAPatterns.some(pattern => pattern.test(userAgent)) || userAgent.length < 10) {
      violations.push('SUSPICIOUS_USER_AGENT');
    }
  }
  
  const bypassHeaders = [
    'x-middleware-subrequest',
    'x-middleware-request-',
    'x-invoke-path',
    'x-invoke-status',
    'x-invoke-query',
    'x-forwarded-proto',
    'x-forwarded-host'
  ];
  
  bypassHeaders.forEach(header => {
    if (request.headers.get(header)) {
      violations.push(`BYPASS_ATTEMPT_${header.toUpperCase()}`);
    }
  });
  
  const clientIP = getClientIP(request);
  if (!checkAdvancedRateLimit(clientIP, request.nextUrl.pathname)) {
    violations.push('RATE_LIMIT_EXCEEDED');
  }
  
  return violations;
}

function getClientIP(request) {
  const forwardedFor = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const remoteAddr = request.headers.get('remote-addr');
  
  let ip = 'unknown';
  
  if (forwardedFor) {
    ip = forwardedFor.split(',')[0].trim();
  } else if (realIP) {
    ip = realIP.trim();
  } else if (remoteAddr) {
    ip = remoteAddr.trim();
  }
  
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  
  if (!ipv4Regex.test(ip)) {
    return 'invalid';
  }
  
  return ip;
}

const rateLimitStore = new Map();
const suspiciousIPs = new Set();

function checkAdvancedRateLimit(ip, path) {
  const now = Date.now();
  const windowMs = 60000; // 1 minuto
  
  const limits = {
    '/api/auth': { max: 5, window: 300000 },    // 5 en 5 minutos
    '/api/foods': { max: 30, window: 60000 },   // 30 por minuto
    '/api/account': { max: 10, window: 60000 }, // 10 por minuto
    'default': { max: 50, window: 60000 }       // 50 por minuto por defecto
  };
  
  const limitKey = Object.keys(limits).find(pattern => path.startsWith(pattern)) || 'default';
  const limit = limits[limitKey] || limits.default;
  
  const key = `${ip}:${limitKey}`;
  const requests = rateLimitStore.get(key) || [];
  
  const validRequests = requests.filter(time => now - time < limit.window);
  
  if (validRequests.length >= limit.max) {
    const violationKey = `violations_${ip}`;
    const violations = rateLimitStore.get(violationKey) || 0;
    rateLimitStore.set(violationKey, violations + 1);
    
    if (violations > 3) {
      suspiciousIPs.add(ip);
    }
    
    return false;
  }
  
  validRequests.push(now);
  rateLimitStore.set(key, validRequests);
  
  if (Math.random() < 0.01) {
    cleanupRateLimit(now);
  }
  
  return true;
}

function cleanupRateLimit(now) {
  for (const [key, requests] of rateLimitStore.entries()) {
    if (key.startsWith('violations_')) continue;
    
    const cleanRequests = requests.filter(time => now - time < 300000); // 5 minutos
    if (cleanRequests.length === 0) {
      rateLimitStore.delete(key);
    } else {
      rateLimitStore.set(key, cleanRequests);
    }
  }
}

async function logCriticalSecurityEvent(eventType, details, request) {
  const securityEvent = {
    id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(),
    timestamp: new Date().toISOString(),
    type: eventType,
    severity: 'CRITICAL',
    clientIP: getClientIP(request),
    userAgent: request.headers.get('user-agent') || 'unknown',
    url: request.url,
    method: request.method,
    details,
    environment: 'production'
  };
    
  return securityEvent;
}

export async function middleware(request) {
  const startTime = Date.now();
  const requestId = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();
  
  try {
    const clientIP = getClientIP(request);
    if (suspiciousIPs.has(clientIP)) {
      await logCriticalSecurityEvent('BLOCKED_SUSPICIOUS_IP', { ip: clientIP }, request);
      return new NextResponse('Access Denied', { status: 403 });
    }
    
    const inputThreats = analyzeRequestInputs(request);
    const criticalThreats = inputThreats.filter(t => t.analysis.risk === 'CRITICAL');
    
    if (criticalThreats.length > 0) {
      await logCriticalSecurityEvent('CRITICAL_INJECTION_DETECTED', {
        threats: criticalThreats,
        requestId
      }, request);
      
      suspiciousIPs.add(clientIP);
      
      return new NextResponse(JSON.stringify({
        error: 'Security violation detected',
        requestId,
        blocked: true
      }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const securityViolations = validateSecurityHeaders(request);
    if (securityViolations.length > 0) {
      await logCriticalSecurityEvent('SECURITY_VIOLATIONS', {
        violations: securityViolations,
        requestId
      }, request);
      
      const criticalViolations = [
        'BYPASS_ATTEMPT',
        'RATE_LIMIT_EXCEEDED'
      ];
      
      const hasCriticalViolation = securityViolations.some(v => 
        criticalViolations.some(cv => v.includes(cv))
      );
      
      if (hasCriticalViolation) {
        return new NextResponse(JSON.stringify({
          error: 'Security validation failed',
          requestId
        }), { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    const response = NextResponse.next();
    
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    response.headers.set('X-Request-ID', requestId);
    
    response.headers.set('Content-Security-Policy', 
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: blob:; " +
      "font-src 'self'; " +
      "connect-src 'self'; " +
      "frame-ancestors 'none';"
    );
    
    response.headers.set('Strict-Transport-Security', 
      'max-age=31536000; includeSubDomains; preload'
    );
    
    if (request.nextUrl.pathname.startsWith('/api/')) {
      response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
      response.headers.set('Pragma', 'no-cache');
      response.headers.set('Expires', '0');
      
      const allowedMethods = {
        '/api/auth': ['POST'],
        '/api/foods': ['GET', 'POST', 'DELETE'],
        '/api/account': ['GET', 'POST']
      };
      
      const routePattern = Object.keys(allowedMethods).find(pattern => 
        request.nextUrl.pathname.startsWith(pattern)
      );
      
      if (routePattern && !allowedMethods[routePattern].includes(request.method)) {
        return new NextResponse('Method Not Allowed', { status: 405 });
      }
    }
    
    const processingTime = Date.now() - startTime;
    response.headers.set('X-Processing-Time', `${processingTime}ms`);
    
    return response;
    
  } catch (error) {
    await logCriticalSecurityEvent('MIDDLEWARE_ERROR', {
      error: error.message,
      stack: error.stack?.substring(0, 500),
      requestId
    }, request);
        
    return NextResponse.next();
  }
}

export const config = {
  matcher: [
    '/api/:path*',
    '/((?!_next/static|_next/image|favicon.ico|public).*)',
  ]
};

export async function analyzeRequestPayload(request) {
  if (request.method !== 'POST') return { threats: [], safe: true };
  
  try {
    const contentType = request.headers.get('content-type') || '';
    
    if (contentType.includes('application/json')) {
      const clonedRequest = request.clone();
      const body = await clonedRequest.text();
      
      if (body) {
        const analysis = detectCriticalThreats(body);
        return {
          threats: analysis.patterns,
          safe: !analysis.detected,
          risk: analysis.risk
        };
      }
    }
    
    return { threats: [], safe: true };
  } catch (error) {
    console.error('Error analyzing payload:', error);
    return { threats: [], safe: true, error: error.message };
  }
}

class SecurityMetrics {
  static metrics = {
    totalRequests: 0,
    blockedRequests: 0,
    threatsDetected: 0,
    suspiciousIPs: new Set(),
    startTime: Date.now()
  };
  
  static incrementRequest() {
    this.metrics.totalRequests++;
  }
  
  static incrementBlocked() {
    this.metrics.blockedRequests++;
  }
  
  static incrementThreats(count = 1) {
    this.metrics.threatsDetected += count;
  }
  
  static addSuspiciousIP(ip) {
    this.metrics.suspiciousIPs.add(ip);
  }
  
  static getMetrics() {
    const uptime = Date.now() - this.metrics.startTime;
    const requestRate = this.metrics.totalRequests / (uptime / 1000 / 60);
    
    return {
      ...this.metrics,
      suspiciousIPs: this.metrics.suspiciousIPs.size,
      uptime: uptime,
      requestRate: Math.round(requestRate * 100) / 100,
      blockRate: this.metrics.totalRequests > 0 
        ? ((this.metrics.blockedRequests / this.metrics.totalRequests) * 100).toFixed(2) + '%'
        : '0%'
    };
  }
}

export function getSecurityMetrics() {
  return {
    metrics: SecurityMetrics.getMetrics(),
    suspiciousIPsCount: suspiciousIPs.size,
    rateLimitEntries: rateLimitStore.size,
    systemStatus: {
      healthy: true,
      uptime: Date.now() - SecurityMetrics.metrics.startTime,
      runtime: 'Edge Runtime',
      timestamp: new Date().toISOString()
    }
  };
}