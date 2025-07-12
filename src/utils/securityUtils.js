export class SecurityUtils {
  
  static generateBasicClientInfo() {
    try {
      return {
        screenResolution: `${screen.width}x${screen.height}`,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        colorDepth: screen.colorDepth,
        timestamp: Date.now(),
        clientHash: btoa(`${screen.width}-${navigator.language}-${Date.now()}`).substring(0, 16)
      };
    } catch (error) {
      return {
        screenResolution: 'unknown',
        language: 'unknown',
        timezone: 'unknown',
        colorDepth: 0,
        timestamp: Date.now(),
        clientHash: 'error'
      };
    }
  }
  
  static clearSensitiveData() {
    try {
      const wasLoggingOut = window.isLoggingOut;
      window.isLoggingOut = true;
      
      localStorage.removeItem('sessionToken');
      localStorage.removeItem('userPreferences');
      localStorage.removeItem('darkMode');
      localStorage.removeItem('securityHash');
      sessionStorage.clear();
      
      if (!wasLoggingOut) {
        setTimeout(() => {
          window.isLoggingOut = false;
        }, 100);
      }
    } catch (error) {    }
  }
  
  static sanitizeForLogging(data) {
    if (!data || typeof data !== 'object') return data;
    
    const sensitiveFields = [
      'password', 'password_hash', 'salt', 'session_token', 
      'sessionToken', 'token', 'secret', 'key', 'auth'
    ];
    
    const sanitized = { ...data };
    
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        if (typeof sanitized[field] === 'string' && sanitized[field].length > 8) {
          sanitized[field] = sanitized[field].substring(0, 4) + '***' + sanitized[field].slice(-4);
        } else {
          sanitized[field] = '***HIDDEN***';
        }
      }
    }
    
    return sanitized;
  }
  
  static validateSessionIntegrity(user, sessionToken) {
    if (!user || !sessionToken) {
      return { valid: false, reason: 'missing_data' };
    }
    
    const requiredFields = ['id', 'username', 'email'];
    for (const field of requiredFields) {
      if (!user[field]) {
        return { valid: false, reason: 'incomplete_user_data' };
      }
    }
    
    if (typeof sessionToken !== 'string' || sessionToken.length < 32) {
      return { valid: false, reason: 'invalid_token_format' };
    }
    
    return { valid: true };
  }
  
  static forceSecurityLogout(reason = 'security_violation') {
    this.clearSensitiveData();
    
    setTimeout(() => {
      window.location.reload();
    }, 1000);
    
    return { 
      logged_out: true, 
      reason, 
      timestamp: new Date().toISOString() 
    };
  }
  
  static generateSimpleHash(data) {
    if (!data) return null;
    
    const critical = {
      userId: data.id,
      username: data.username,
      email: data.email
    };
    
    return btoa(JSON.stringify(critical)).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }
}