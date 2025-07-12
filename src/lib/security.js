import crypto from 'crypto';
import bcrypt from 'bcryptjs';

class DatabaseHardening {
  static createSecureQuery() {
    return {
      select: (table, columns = '*', conditions = {}) => {
        const allowedTables = ['users', 'foods', 'user_sessions', 'security_logs'];
        const allowedColumns = {
          users: ['id', 'username', 'email', 'created_at', 'daily_calorie_goal', 'password_hash', 'salt', 'is_active', 'failed_login_attempts', 'last_failed_login', 'account_locked_until'],
          foods: ['id', 'name', 'calories', 'consumed_at', 'date_consumed'],
          user_sessions: ['id', 'user_id', 'expires_at', 'created_at', 'session_token', 'is_active', 'ip_address', 'user_agent'],
          security_logs: ['id', 'user_id', 'action', 'created_at', 'ip_address', 'user_agent', 'details']
        };
        
        if (!allowedTables.includes(table)) {
          throw new Error(`Table '${table}' not allowed`);
        }
        
        if (columns !== '*') {
          const tableColumns = allowedColumns[table];
          const requestedColumns = Array.isArray(columns) ? columns : [columns];
          
          for (const col of requestedColumns) {
            if (!tableColumns.includes(col)) {
              throw new Error(`Column '${col}' not allowed for table '${table}'`);
            }
          }
        }
        
        const safeColumns = columns === '*' ? columns : 
          (Array.isArray(columns) ? columns.join(', ') : columns);
        
        let query = `SELECT ${safeColumns} FROM ${table}`;
        const params = [];
        
        if (Object.keys(conditions).length > 0) {
          const whereClause = Object.keys(conditions)
            .map(key => `${key} = ?`)
            .join(' AND ');
          query += ` WHERE ${whereClause}`;
          params.push(...Object.values(conditions));
        }
        
        return { query, params };
      },
      
      insert: (table, data) => {
        const allowedTables = ['users', 'foods', 'user_sessions', 'security_logs'];
        
        if (!allowedTables.includes(table)) {
          throw new Error(`Insert not allowed for table '${table}'`);
        }
        
        const columns = Object.keys(data);
        const placeholders = columns.map(() => '?').join(', ');
        const query = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`;
        const params = Object.values(data);
        
        return { query, params };
      },
      
      update: (table, data, conditions) => {
        const allowedTables = ['users', 'foods', 'user_sessions'];
        
        if (!allowedTables.includes(table)) {
          throw new Error(`Update not allowed for table '${table}'`);
        }
        
        if (!conditions || Object.keys(conditions).length === 0) {
          throw new Error('Update without conditions not allowed');
        }
        
        const setClause = Object.keys(data)
          .map(key => `${key} = ?`)
          .join(', ');
        
        const whereClause = Object.keys(conditions)
          .map(key => `${key} = ?`)
          .join(' AND ');
        
        const query = `UPDATE ${table} SET ${setClause} WHERE ${whereClause}`;
        const params = [...Object.values(data), ...Object.values(conditions)];
        
        return { query, params };
      }
    };
  }

  static async executeSecureQuery(queryObj, additionalValidation = null) {
    try {
      if (additionalValidation) {
        const isValid = await additionalValidation(queryObj);
        if (!isValid) {
          throw new Error('Additional validation failed');
        }
      }
      
      const suspiciousPatterns = [
        /(\bunion\b.*\bselect\b)/i,
        /((\%27)|(\'))\s*(\bor\b|\band\b)\s*((\%27)|(\'))/i,
        /\b(sleep|benchmark|waitfor)\s*\(/i,
        /;\s*(drop|create|alter|insert|update|delete)\b/i,
        /\b(load_file|into\s+outfile|dumpfile)\b/i,
        /(\/\*.*\*\/|--\s|#)/,
        /0x[0-9a-f]+/i
      ];
      
      const fullQuery = `${queryObj.query} ${JSON.stringify(queryObj.params)}`;
      
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(fullQuery)) {
          throw new Error(`Suspicious SQL pattern detected: ${pattern.source}`);
        }
      }
      
      const { query } = await import('./db.js');
      return await Promise.race([
        query(queryObj.query, queryObj.params),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), 10000)
        )
      ]);
      
    } catch (error) {
      throw new Error('Database operation failed');
    }
  }
}

class AuthenticationHardening {
  static async hashPassword(password) {
    const saltRounds = 12;
    const hash = await bcrypt.hash(password, saltRounds);
    const salt = await bcrypt.genSalt(10);
    return { hash, salt };
  }

  static async verifyPassword(password, storedHash, storedSalt) {
    try {
      if (storedHash && storedHash.startsWith('$2')) {
        return await bcrypt.compare(password, storedHash);
      }
      const crypto = require('crypto');
      
      if (storedSalt && typeof storedSalt === 'string') {
        const sha256Hash = crypto.createHash('sha256').update(password + storedSalt).digest('hex');
        if (sha256Hash === storedHash) {
          return true;
        }
        
        const md5Hash = crypto.createHash('md5').update(password + storedSalt).digest('hex');
        if (md5Hash === storedHash) {
          return true;
        }
        
        const sha512Hash = crypto.createHash('sha512').update(password + storedSalt).digest('hex');
        if (sha512Hash === storedHash) {
          return true;
        }
        
        const simpleHash = crypto.createHash('sha256').update(storedSalt + password).digest('hex');
        if (simpleHash === storedHash) {
          return true;
        }
      }
      
      if (storedHash === password) {
        return true;
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }
  
  static async validateTokenUltraSecure(token, request) {
    const violations = [];
    
    try {
      if (!token || typeof token !== 'string' || token.length < 64) {
        violations.push('INVALID_TOKEN_FORMAT');
      }
      
      if (!/^[a-zA-Z0-9]+$/.test(token)) {
        violations.push('INVALID_TOKEN_CHARACTERS');
      }
      
      const commonTokens = [
        'a'.repeat(64), '1'.repeat(64), '0'.repeat(64),
        'admin', 'test', 'demo', 'default'
      ];
      
      if (commonTokens.includes(token) || token.length < 32) {
        violations.push('WEAK_TOKEN');
      }
      
      const queryObj = {
        query: `
          SELECT us.user_id, us.expires_at, us.ip_address, us.user_agent,
                 u.username, u.email, u.is_active, u.failed_login_attempts,
                 u.account_locked_until, u.daily_calorie_goal
          FROM user_sessions us
          INNER JOIN users u ON us.user_id = u.id
          WHERE us.session_token = ? 
          AND us.is_active = 1 
          AND us.expires_at > NOW()
          AND u.is_active = 1
        `,
        params: [token]
      };
      
      const sessions = await DatabaseHardening.executeSecureQuery(queryObj);
      
      if (sessions.length === 0) {
        violations.push('SESSION_NOT_FOUND');
      }
      
      const session = sessions[0];
      
      if (session?.account_locked_until && new Date(session.account_locked_until) > new Date()) {
        violations.push('ACCOUNT_LOCKED');
      }
      
      if (session?.failed_login_attempts >= 5) {
        violations.push('TOO_MANY_FAILED_ATTEMPTS');
      }
      
      const currentIP = this.getSecureClientIP(request);
      if (session?.ip_address && session.ip_address !== currentIP) {
        const ipParts = session.ip_address.split('.');
        const currentParts = currentIP.split('.');
        
        if (ipParts.slice(0, 3).join('.') !== currentParts.slice(0, 3).join('.')) {
          violations.push('IP_MISMATCH');
        }
      }
      
      const sessionUA = session?.user_agent || '';
      const currentUA = request.headers.get('user-agent') || '';
      
      const extractUACore = (ua) => {
        const match = ua.match(/(Chrome|Firefox|Safari|Edge)\/[\d.]+/);
        return match ? match[0] : ua.substring(0, 50);
      };
      
      if (sessionUA && extractUACore(sessionUA) !== extractUACore(currentUA)) {
        violations.push('USER_AGENT_MISMATCH');
      }
      
      const rateLimitKey = `auth_validate_${currentIP}_${session?.user_id}`;
      if (!this.checkAuthRateLimit(rateLimitKey, 100, 60000)) {
        violations.push('VALIDATION_RATE_LIMIT');
      }
      
      if (violations.length > 0) {
        await this.logSuspiciousAuth({
          violations,
          token: token.substring(0, 8) + '...',
          ip: currentIP,
          userAgent: currentUA.substring(0, 100),
          timestamp: new Date().toISOString()
        });
        
        throw new Error(`Authentication failed: ${violations.join(', ')}`);
      }
      
      return {
        valid: true,
        user: {
          id: session.user_id,
          username: session.username,
          email: session.email,
          daily_calorie_goal: session.daily_calorie_goal
        },
        session: {
          ip: session.ip_address,
          userAgent: session.user_agent,
          expires: session.expires_at
        }
      };
      
    } catch (error) {
      throw new Error('Authentication validation failed');
    }
  }
  
  static getSecureClientIP(request) {
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
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      return 'invalid';
    }
    
    return ip;
  }
  
  static rateLimitStore = new Map();
  
  static checkAuthRateLimit(key, maxAttempts, windowMs) {
    const now = Date.now();
    const record = this.rateLimitStore.get(key) || { attempts: 0, resetTime: now + windowMs };
    
    if (now > record.resetTime) {
      record.attempts = 1;
      record.resetTime = now + windowMs;
    } else {
      record.attempts++;
    }
    
    this.rateLimitStore.set(key, record);
    
    return record.attempts <= maxAttempts;
  }
  
  static async logSuspiciousAuth(details) {
    try {
      const logEntry = {
        type: 'SUSPICIOUS_AUTH_ATTEMPT',
        details,
        severity: 'HIGH',
        timestamp: new Date().toISOString()
      };
            
      const secureQuery = DatabaseHardening.createSecureQuery();
      const insertObj = secureQuery.insert('security_logs', {
        user_id: null,
        action: 'SUSPICIOUS_AUTH_ATTEMPT',
        ip_address: details.ip,
        user_agent: details.userAgent,
        details: JSON.stringify(details)
      });
      
      await DatabaseHardening.executeSecureQuery(insertObj);
      
    } catch (error) {}
  }
}

class InputHardening {
  
  static validateInputUltraSecure(input, type, context = {}) {
    const violations = [];
    
    if (input === null || input === undefined) {
      if (context.required !== false) {
        violations.push('REQUIRED_FIELD_MISSING');
      } else {
        return { valid: true, sanitized: null };
      }
    }
    
    let sanitized = input;
    
    switch (type) {
      case 'username':
        sanitized = this.validateUsername(input, violations);
        break;
      case 'email':
        sanitized = this.validateEmail(input, violations);
        break;
      case 'password':
        sanitized = this.validatePassword(input, violations);
        break;
      case 'integer':
        sanitized = this.validateInteger(input, violations, context);
        break;
      case 'string':
        sanitized = this.validateString(input, violations, context);
        break;
      case 'json':
        sanitized = this.validateJSON(input, violations);
        break;
      default:
        violations.push('UNKNOWN_INPUT_TYPE');
    }
    
    if (typeof sanitized === 'string') {
      const maliciousPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /data:\s*[^;]+;base64/gi,
        /(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bcreate\b|\balter\b)/gi,
        /\.\.\/.*\.\.\//g,
        /[;&|`$(){}]/g,
        /\x00/g,
        /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g
      ];
      
      for (const pattern of maliciousPatterns) {
        if (pattern.test(sanitized)) {
          violations.push(`MALICIOUS_PATTERN_DETECTED: ${pattern.source.substring(0, 50)}`);
        }
      }
    }
    
    if (violations.length > 0) {
      throw new Error(`Input validation failed: ${violations.join(', ')}`);
    }
    
    return { valid: true, sanitized };
  }
  
  static validateUsername(input, violations) {
    if (typeof input !== 'string') {
      violations.push('USERNAME_MUST_BE_STRING');
      return input;
    }
    
    if (input.length < 3 || input.length > 30) {
      violations.push('USERNAME_LENGTH_INVALID');
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(input)) {
      violations.push('USERNAME_CONTAINS_INVALID_CHARACTERS');
    }
    
    if (/^[0-9_]/.test(input)) {
      violations.push('USERNAME_INVALID_START_CHARACTER');
    }
    
    const forbiddenUsernames = [
      'admin', 'administrator', 'root', 'system', 'test', 'demo',
      'null', 'undefined', 'api', 'www', 'ftp', 'mail', 'email',
      'support', 'help', 'info', 'contact', 'sales', 'noreply'
    ];
    
    if (forbiddenUsernames.includes(input.toLowerCase())) {
      violations.push('USERNAME_FORBIDDEN');
    }
    
    return input.trim().toLowerCase();
  }
  
  static validateEmail(input, violations) {
    if (typeof input !== 'string') {
      violations.push('EMAIL_MUST_BE_STRING');
      return input;
    }
    
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(input)) {
      violations.push('EMAIL_INVALID_FORMAT');
    }
    
    if (input.length > 320) {
      violations.push('EMAIL_TOO_LONG');
    }
    
    const suspiciousDomains = [
      '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
      'mailinator.com', 'yopmail.com', 'temp-mail.org'
    ];
    
    const domain = input.split('@')[1]?.toLowerCase();
    if (suspiciousDomains.includes(domain)) {
      violations.push('EMAIL_TEMPORARY_DOMAIN');
    }
    
    return input.trim().toLowerCase();
  }
  
  static validatePassword(input, violations) {
    if (typeof input !== 'string') {
      violations.push('PASSWORD_MUST_BE_STRING');
      return input;
    }
    
    if (input.length < 8) {
      violations.push('Debe tener al menos 8 caracteres');
    }
    
    if (input.length > 128) {
      violations.push('PASSWORD_TOO_LONG');
    }
    
    const requirements = [
      { pattern: /[a-z]/, message: 'Debe incluir al menos una letra minúscula' },
      { pattern: /[A-Z]/, message: 'Debe incluir al menos una letra mayúscula' },
      { pattern: /[0-9]/, message: 'Debe incluir al menos un número' },
      { pattern: /[^a-zA-Z0-9]/, message: 'Debe incluir al menos un carácter especial' }
    ];
    
    for (const req of requirements) {
      if (!req.pattern.test(input)) {
        violations.push(req.message);
      }
    }
    
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123',
      'password123', 'admin123', 'letmein', 'welcome', 'monkey'
    ];
    
    if (commonPasswords.includes(input.toLowerCase())) {
      violations.push('PASSWORD_TOO_COMMON');
    }
    
    if (/(.)\1{3,}/.test(input)) {
      violations.push('PASSWORD_REPEATED_CHARACTERS');
    }
    
    const sequences = ['123', 'abc', 'qwe', 'asd', 'zxc'];
    for (const seq of sequences) {
      if (input.toLowerCase().includes(seq)) {
        violations.push('PASSWORD_CONTAINS_SEQUENCE');
      }
    }
    
    return input;
  }
  
  static validateInteger(input, violations, context) {
    let num;
    
    if (typeof input === 'number') {
      num = input;
    } else if (typeof input === 'string') {
      if (!/^-?\d+$/.test(input.trim())) {
        violations.push('INTEGER_INVALID_FORMAT');
        return input;
      }
      num = parseInt(input.trim(), 10);
    } else {
      violations.push('INTEGER_INVALID_TYPE');
      return input;
    }
    
    if (isNaN(num) || !Number.isInteger(num)) {
      violations.push('INTEGER_CONVERSION_FAILED');
      return input;
    }
    
    const min = context.min !== undefined ? context.min : -2147483648; // 32-bit signed int min
    const max = context.max !== undefined ? context.max : 2147483647;  // 32-bit signed int max
    
    if (num < min || num > max) {
      violations.push(`INTEGER_OUT_OF_RANGE_${min}_${max}`);
    }
    
    return num;
  }
  
  static validateString(input, violations, context) {
    if (typeof input !== 'string') {
      violations.push('STRING_INVALID_TYPE');
      return String(input);
    }
    
    const minLength = context.minLength || 0;
    const maxLength = context.maxLength || 10000;
    
    if (input.length < minLength) {
      violations.push(`STRING_TOO_SHORT_MIN_${minLength}`);
    }
    
    if (input.length > maxLength) {
      violations.push(`STRING_TOO_LONG_MAX_${maxLength}`);
    }
    
    let sanitized = input.trim();
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
    
    sanitized = sanitized
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
    
    return sanitized;
  }
}

export class Security {
  static async hashPassword(password) {
    return AuthenticationHardening.hashPassword(password);
  }

  static async verifyPassword(password, hash, salt) {
    return AuthenticationHardening.verifyPassword(password, hash, salt);
  }

  static sanitizeInput(input) {
    try {
      return InputHardening.validateInputUltraSecure(input, 'string').sanitized;
    } catch (error) {
      throw new Error('Invalid input');
    }
  }

  static validateEmail(email) {
    try {
      const result = InputHardening.validateInputUltraSecure(email, 'email');
      return result.valid;
    } catch (error) {
      return false;
    }
  }

  static validateUsername(username) {
    try {
      const result = InputHardening.validateInputUltraSecure(username, 'username');
      return result.valid;
    } catch (error) {
      return false;
    }
  }

  static validatePassword(password) {
    try {
      InputHardening.validateInputUltraSecure(password, 'password');
      return [];
    } catch (error) {
      const errorMessage = error.message.replace('Input validation failed: ', '');
      return errorMessage.split(', ').filter(msg => !msg.includes('VALIDATION_FAILED'));
    }
  }

  static generateRandomToken(length = 64) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').substring(0, length);
  }

  static getClientIP(req) {
    return AuthenticationHardening.getSecureClientIP(req);
  }

  static checkRateLimit(key, maxAttempts, windowMs) {
    return AuthenticationHardening.checkAuthRateLimit(key, maxAttempts, windowMs);
  }

  static async logSecurityEvent(userId, action, req, details = {}) {
    try {
      const secureQuery = DatabaseHardening.createSecureQuery();
      const insertObj = secureQuery.insert('security_logs', {
        user_id: userId,
        action: action,
        ip_address: this.getClientIP(req),
        user_agent: req.headers.get?.('user-agent') || req.headers['user-agent'] || 'unknown',
        details: JSON.stringify(details)
      });

      await DatabaseHardening.executeSecureQuery(insertObj);
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  static async isAccountLocked(identifier) {
    try {
      const queryObj = {
        query: `
          SELECT account_locked_until, failed_login_attempts 
          FROM users 
          WHERE username = ? OR email = ?
        `,
        params: [identifier, identifier]
      };

      const users = await DatabaseHardening.executeSecureQuery(queryObj);
      const user = users[0];

      if (user?.account_locked_until) {
        return new Date() < new Date(user.account_locked_until);
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  static async incrementFailedAttempts(identifier) {
    try {
      const queryObj = {
        query: `
          UPDATE users 
          SET failed_login_attempts = failed_login_attempts + 1,
              last_failed_login = NOW(),
              account_locked_until = CASE 
                WHEN failed_login_attempts + 1 >= 5 
                THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE)
                ELSE account_locked_until
              END
          WHERE username = ? OR email = ?
        `,
        params: [identifier, identifier]
      };

      await DatabaseHardening.executeSecureQuery(queryObj);
    } catch (error) {
      console.error('Failed to increment failed attempts:', error);
    }
  }

  static async resetFailedAttempts(userId) {
    try {
      const secureQuery = DatabaseHardening.createSecureQuery();
      const updateObj = secureQuery.update('users', {
        failed_login_attempts: 0,
        last_failed_login: null,
        account_locked_until: null
      }, { id: userId });

      await DatabaseHardening.executeSecureQuery(updateObj);
    } catch (error) {
      console.error('Failed to reset failed attempts:', error);
    }
  }

  static async authenticateRequest(req) {
    let authHeader = null;
    
    if (req.headers && typeof req.headers.get === 'function') {
      authHeader = req.headers.get('authorization');
    } else if (req.headers && req.headers.authorization) {
      authHeader = req.headers.authorization;
    }
    
    let token = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
    
    if (!token) {
      throw new Error('Token de autorización requerido');
    }

    const validation = await AuthenticationHardening.validateTokenUltraSecure(token, req);
    
    return validation.user;
  }

  static async migratePasswordToBcrypt(userId, plainPassword) {
    try {      
      const { hash, salt } = await this.hashPassword(plainPassword);
      const secureQuery = DatabaseHardening.createSecureQuery();
      const updateObj = secureQuery.update('users', {
        password_hash: hash,
        salt: salt
      }, { id: userId })
      await DatabaseHardening.executeSecureQuery(updateObj);
      return true;
    } catch (error) {
      return false;
    }
  }
}

export {
  DatabaseHardening,
  AuthenticationHardening,
  InputHardening
};