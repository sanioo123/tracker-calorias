"use client";

import React, { useState, useEffect } from 'react';
import { Target, Utensils, Heart, Award, TrendingUp, LogOut, Plus, Settings } from 'lucide-react';
import Login from './Login';
import Register from './Register';
import AccountSettings from './AccountSettings';

const API_BASE = '/api';

const SecurityUtils = {
  protectionIntervals: [],

  clearSensitiveData() {
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
      
    } catch (error) {
      return "error"
    }
  },

  clearAllProtections() {
    this.protectionIntervals.forEach(interval => {
      if (interval) clearInterval(interval);
    });
    this.protectionIntervals = [];

    if (window.originalLocalStorageSetItem) {
      localStorage.setItem = window.originalLocalStorageSetItem;
      delete window.originalLocalStorageSetItem;
    }
    if (window.originalLocalStorageRemoveItem) {
      localStorage.removeItem = window.originalLocalStorageRemoveItem;
      delete window.originalLocalStorageRemoveItem;
    }
  },

  generateDeviceFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Security fingerprint', 2, 2);
      
      const fingerprint = {
        screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        platform: navigator.platform,
        userAgent: navigator.userAgent.substring(0, 100),
        canvas: canvas.toDataURL().substring(0, 50),
        memory: navigator.deviceMemory || 'unknown',
        cores: navigator.hardwareConcurrency || 'unknown'
      };
      
      return btoa(JSON.stringify(fingerprint)).substring(0, 32);
    } catch (error) {
      return 'fingerprint_error';
    }
  },

  verifySystemTime() {
    const serverTime = Date.now();
    const clientTime = new Date().getTime();
    const timeDiff = Math.abs(serverTime - clientTime);

    if (timeDiff > 300000) {
      return { valid: false, reason: 'system_time_manipulation' };
    }
    
    return { valid: true };
  },

  generateIntegrityHash(data) {
    if (!data) return null;
    const critical = {
      userId: data.id,
      username: data.username,
      email: data.email
    };
    return btoa(JSON.stringify(critical)).replace(/[^a-zA-Z0-9]/g, '');
  },

  verifyDataIntegrity(currentUser, sessionToken) {
    const violations = [];
    try {
      const storedToken = localStorage.getItem('sessionToken');
      if (storedToken && storedToken !== sessionToken) {
        violations.push('session_token_mismatch');
      }

      const currentHash = this.generateIntegrityHash(currentUser);
      const storedHash = localStorage.getItem('securityHash');
      
      if (storedHash) {
        if (storedHash !== currentHash) {
          violations.push('user_data_modified');
        }
      } else {
        localStorage.setItem('securityHash', currentHash);
      }

      if (!currentUser.id || (typeof currentUser.id !== 'string' && typeof currentUser.id !== 'number')) {
        violations.push('invalid_user_id');
      }
      if (!currentUser.username || typeof currentUser.username !== 'string') {
        violations.push('invalid_user_username');
      }
      if (!currentUser.email || typeof currentUser.email !== 'string') {
        violations.push('invalid_user_email');
      }

      if (!sessionToken || typeof sessionToken !== 'string' || sessionToken.length < 32) {
        violations.push('invalid_token_format');
      }

      if (violations.length === 0 && storedHash) {
        localStorage.setItem('securityHash', currentHash);
      }
    } catch (error) {
      violations.push('integrity_check_failed');
    }

    return violations;
  },

  setupStorageProtection(sessionToken, onViolation) {
    if (!window.originalLocalStorageSetItem) {
      window.originalLocalStorageSetItem = localStorage.setItem;
    }
    if (!window.originalLocalStorageRemoveItem) {
      window.originalLocalStorageRemoveItem = localStorage.removeItem;
    }

    localStorage.setItem = function(key, value) {
      if (key === 'sessionToken') {
        const isLegitimate = window.isLoggingOut || window.isLoggingIn || value === sessionToken;
        if (!isLegitimate) {
          onViolation('session_token_manipulation');
          return;
        }
      }
      return window.originalLocalStorageSetItem.call(this, key, value);
    };
    
    localStorage.removeItem = function(key) {
      if (key === 'sessionToken') {
        const isLegitimateLogout = window.isLoggingOut || false;
        if (!isLegitimateLogout) {
          onViolation('session_token_removal');
          return;
        }
      }
      return window.originalLocalStorageRemoveItem.call(this, key);
    };
    
    const checkInterval = setInterval(() => {
      const currentToken = localStorage.getItem('sessionToken');
      if (currentToken !== sessionToken && !window.isLoggingOut && !window.isLoggingIn) {
        onViolation('external_token_modification');
        clearInterval(checkInterval);
      }
    }, 3000);
    
    this.protectionIntervals.push(checkInterval);
    
    return checkInterval;
  },

  forceSecurityLogout(reason = 'security_violation') {
    this.clearSensitiveData();
    setTimeout(() => {
      window.location.reload();
    }, 1000);
    return { logged_out: true, reason, timestamp: new Date().toISOString() };
  },

  validateSessionIntegrity(user, sessionToken) {
    if (!user || !sessionToken) {
      return { valid: false, reason: 'missing_data' };
    }
    
    if (!user.id || (typeof user.id !== 'string' && typeof user.id !== 'number')) {
      return { valid: false, reason: 'invalid_user_id' };
    }
    if (!user.username || typeof user.username !== 'string') {
      return { valid: false, reason: 'invalid_username' };
    }
    if (!user.email || typeof user.email !== 'string') {
      return { valid: false, reason: 'invalid_email' };
    }
    
    if (typeof sessionToken !== 'string' || sessionToken.length < 32) {
      return { valid: false, reason: 'invalid_token_format' };
    }
    
    return { valid: true };
  },

  sanitizeForLogging(data) {
    if (!data || typeof data !== 'object') return data;
    const sensitiveFields = ['password', 'password_hash', 'salt', 'session_token', 'sessionToken', 'token'];
    const sanitized = { ...data };
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = sanitized[field].length > 8 
          ? sanitized[field].substring(0, 4) + '***' + sanitized[field].slice(-4)
          : '***HIDDEN***';
      }
    }
    return sanitized;
  }
};

const CalorieTracker = () => {
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState('login');
  const [foods, setFoods] = useState([]);
  const [dailyGoal, setDailyGoal] = useState(2000);
  const [newFood, setNewFood] = useState({ name: '', calories: '' });
  const [showAddForm, setShowAddForm] = useState(false);
  const [sessionToken, setSessionToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showWelcome, setShowWelcome] = useState(false);
  const [welcomeUser, setWelcomeUser] = useState(null);
  const [darkMode, setDarkMode] = useState(false);
  const [currentView, setCurrentView] = useState('dashboard');
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const motivationalMessages = [
    "¡Cada elección saludable te acerca a tus objetivos! 💪",
    "Tu cuerpo es tu templo, cuídalo con amor 🌟",
    "Pequeños cambios, grandes resultados 🚀",
    "La salud es la verdadera riqueza 💎",
    "¡Hoy es un gran día para cuidar tu bienestar! ☀️",
    "Recuerda: el progreso es más importante que la perfección 🌱"
  ];

  const healthTips = [
    "💧 Bebe al menos 8 vasos de agua al día",
    "🥗 Incluye 5 porciones de frutas y verduras diariamente",
    "🚶‍♀️ Camina al menos 30 minutos cada día",
    "😴 Duerme entre 7-9 horas para una mejor recuperación",
    "🧘‍♀️ Practica la respiración profunda para reducir el estrés",
    "🍎 Prefiere alimentos naturales sobre procesados"
  ];

  const [currentMessage, setCurrentMessage] = useState(0);
  const [currentTip, setCurrentTip] = useState(0);

  useEffect(() => {
    const token = localStorage.getItem('sessionToken');
    if (token) {
      const savedDarkMode = localStorage.getItem('darkMode') === 'true';
      setDarkMode(savedDarkMode);
      verifySession(token);
    } else {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentMessage((prev) => (prev + 1) % motivationalMessages.length);
      setCurrentTip((prev) => (prev + 1) % healthTips.length);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (user && sessionToken) {
      loadFoods();
    }
  }, [user, sessionToken]);

  useEffect(() => {
    if (user && sessionToken) {
      const verifyInterval = setInterval(async () => {
        try {
          await apiCall('auth?action=verify', {
            method: 'POST',
            body: JSON.stringify({ session_token: sessionToken })
          });
        } catch (error) {
          await handleLogout();
        }
      }, 300000); // 5 minutos

      const rotateInterval = setInterval(async () => {
        try {
          const deviceFingerprint = SecurityUtils.generateDeviceFingerprint();

          const data = await apiCall('auth/rotate', {
            method: 'POST',
            body: JSON.stringify({ 
              current_token: sessionToken,
              device_fingerprint: deviceFingerprint 
            })
          });
          
          setSessionToken(data.session_token);
          localStorage.setItem('sessionToken', data.session_token);
          
        } catch (error) {}
      }, 1800000); // 30 minutos

      return () => {
        clearInterval(verifyInterval);
        clearInterval(rotateInterval);
      };
    }
  }, [user, sessionToken]);

  useEffect(() => {
    if (user && sessionToken) {
      const handleSecurityViolation = (violationType) => {
        SecurityUtils.forceSecurityLogout(violationType);
      };
      
      const violations = SecurityUtils.verifyDataIntegrity(user, sessionToken);
      if (violations.length > 0) {
        handleSecurityViolation(`initial_integrity_failed: ${violations.join(', ')}`);
        return;
      }
      
      const storageInterval = SecurityUtils.setupStorageProtection(sessionToken, handleSecurityViolation);
      
      const integrityInterval = setInterval(() => {
        const currentViolations = SecurityUtils.verifyDataIntegrity(user, sessionToken);
        if (currentViolations.length > 0) {
          handleSecurityViolation(`periodic_check_failed: ${currentViolations.join(', ')}`);
          clearInterval(integrityInterval);
          clearInterval(storageInterval);
        }
      }, 30000);
      
      return () => {
        clearInterval(storageInterval);
        clearInterval(integrityInterval);
        SecurityUtils.clearAllProtections();
      };
    }
  }, [user, sessionToken]);

  const apiCall = async (endpoint, options = {}) => {
    const url = `${API_BASE}/${endpoint}`;
    const token = sessionToken || localStorage.getItem('sessionToken');
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` })
      },
      ...options
    };

    const response = await fetch(url, config);
    const data = await response.json();

    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem('sessionToken');
        setUser(null);
        setSessionToken(null);
        setCurrentView('dashboard');
      }
      throw new Error(data.error || 'API call failed');
    }

    return data;
  };

  const verifySession = async (token) => {
    try {
      const data = await apiCall('auth?action=verify', {
        method: 'POST',
        body: JSON.stringify({ session_token: token })
      });

      const validation = SecurityUtils.validateSessionIntegrity(data.user, token);
      if (!validation.valid) {
        SecurityUtils.forceSecurityLogout(validation.reason);
        return;
      }

      setUser(data.user);
      setDailyGoal(data.user.daily_calorie_goal);
      setSessionToken(token);
    } catch (error) {
      SecurityUtils.clearSensitiveData();
    }
    setLoading(false);
  };

  const handleLogin = async (credentials) => {
    try {
      window.isLoggingIn = true;
      
      const data = await apiCall('auth?action=login', {
        method: 'POST',
        body: JSON.stringify(credentials)
      });

      setWelcomeUser(data.user);
      setShowWelcome(true);

      setTimeout(() => {
        setUser(data.user);
        setDailyGoal(data.user.daily_calorie_goal);
        setSessionToken(data.session_token);
        localStorage.setItem('sessionToken', data.session_token);
        
        const savedDarkMode = localStorage.getItem('darkMode') === 'true';
        setDarkMode(savedDarkMode);
        
        setShowWelcome(false);
        setWelcomeUser(null);
        
        setTimeout(() => {
          window.isLoggingIn = false;
        }, 1000);
      }, 3000);
      
      return { success: true };
    } catch (error) {
      window.isLoggingIn = false;
      return { success: false, error: error.message };
    }
  };

  const handleRegister = async (userData) => {
    try {
      await apiCall('auth?action=register', {
        method: 'POST',
        body: JSON.stringify(userData)
      });

      return await handleLogin({
        username: userData.username,
        password: userData.password
      });
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const handleLogout = async () => {
    setIsLoggingOut(true);
    window.isLoggingOut = true;
        
    try {
      await apiCall('auth?action=logout', {
        method: 'POST',
        body: JSON.stringify({ session_token: sessionToken })
      });
    } catch (error) {}

    SecurityUtils.clearAllProtections();
    SecurityUtils.clearSensitiveData();

    setUser(null);
    setSessionToken(null);
    setFoods([]);
    setDailyGoal(2000);
    setCurrentView('dashboard');
    setDarkMode(false);
    
    setTimeout(() => {
      setIsLoggingOut(false);
      window.isLoggingOut = false;
    }, 2000);
  };

  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem('darkMode', newDarkMode.toString());
  };

  const loadFoods = async () => {
    try {
      const data = await apiCall('foods');
      setFoods(data.foods);
    } catch (error) {
      console.error('Failed to load foods:', error);
    }
  };

  const addFood = async () => {
    if (!newFood.name.trim() || !newFood.calories) return;

    try {
      const data = await apiCall('foods', {
        method: 'POST',
        body: JSON.stringify({
          name: newFood.name.trim(),
          calories: parseInt(newFood.calories)
        })
      });

      setFoods([data.food, ...foods]);
      setNewFood({ name: '', calories: '' });
      setShowAddForm(false);
    } catch (error) {
      alert('Error adding food: ' + error.message);
    }
  };

  const removeFood = async (foodId) => {
    try {
      await apiCall(`foods?id=${foodId}`, {
        method: 'DELETE'
      });

      setFoods(foods.filter(food => food.id !== foodId));
    } catch (error) {
      alert('Error removing food: ' + error.message);
    }
  };

  const updateDailyGoalAPI = async (newGoal) => {
    try {
      await apiCall('foods/goal', {
        method: 'POST',
        body: JSON.stringify({ daily_goal: newGoal })
      });
    } catch (error) {
      console.error('Failed to update goal:', error);
    }
  };

  const handleGoalChange = (e) => {
    const newGoal = parseInt(e.target.value) || 2000;
    setDailyGoal(newGoal);
    updateDailyGoalAPI(newGoal);
  };

  const resetDay = async () => {
    if (!confirm('¿Estás seguro de que quieres eliminar todos los alimentos del día?')) return;

    try {
      for (const food of foods) {
        await apiCall(`foods?id=${food.id}`, {
          method: 'DELETE'
        });
      }
      setFoods([]);
    } catch (error) {
      alert('Error resetting day: ' + error.message);
    }
  };

  const totalCalories = foods.reduce((sum, food) => sum + food.calories, 0);
  const remainingCalories = dailyGoal - totalCalories;
  const progressPercentage = Math.min((totalCalories / dailyGoal) * 100, 100);

  const DarkModeToggle = () => (
    <button
      onClick={toggleDarkMode}
      className={`relative inline-flex h-8 w-16 items-center rounded-full transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 shadow-inner ${
        darkMode ? 'bg-indigo-900' : 'bg-sky-300'
      }`}
      title={darkMode ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro'}
    >
      <span
        className={`inline-flex items-center justify-center h-6 w-6 transform rounded-full bg-white transition-all duration-300 shadow-lg ${
          darkMode ? 'translate-x-9' : 'translate-x-1'
        }`}
      >
        <span className="text-xs">
          {darkMode ? '🌙' : '☀️'}
        </span>
      </span>
      
      <span className="sr-only">Toggle dark mode</span>
    </button>
  );

  const WelcomeAnimation = ({ user }) => (
    <div className="fixed inset-0 bg-gradient-to-br from-blue-600 via-purple-600 to-green-600 flex items-center justify-center z-50">
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute animate-floating-particles opacity-20"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 2}s`,
              animationDuration: `${2 + Math.random() * 2}s`
            }}
          >
            <div className="w-4 h-4 bg-white rounded-full"></div>
          </div>
        ))}
      </div>

      <div className="text-center z-10">
        <div className="mb-8 animate-welcome-bounce">
          <div className="glass-effect rounded-full p-8 mx-auto w-32 h-32 flex items-center justify-center">
            <Utensils className="w-16 h-16 text-white animate-welcome-pulse" />
          </div>
        </div>

        <div className="space-y-4">
          <h1 className="text-6xl font-bold text-white animate-welcome-fade-in-up" style={{ animationDelay: '0.5s' }}>
            ¡Bienvenido!
          </h1>
          
          <h2 className="text-3xl font-semibold text-white/90 animate-welcome-fade-in-up" style={{ animationDelay: '1s' }}>
            Hola, <span className="text-yellow-300">{user?.username}</span>
          </h2>
          
          <p className="text-xl text-white/80 animate-welcome-fade-in-up" style={{ animationDelay: '1.5s' }}>
            ¡Listo para cuidar tu salud hoy! 🌟
          </p>
        </div>

        <div className="mt-12 animate-welcome-fade-in-up" style={{ animationDelay: '2s' }}>
          <div className="flex items-center justify-center space-x-2">
            <div className="w-3 h-3 bg-white rounded-full animate-welcome-bounce" style={{ animationDelay: '0s' }}></div>
            <div className="w-3 h-3 bg-white rounded-full animate-welcome-bounce" style={{ animationDelay: '0.2s' }}></div>
            <div className="w-3 h-3 bg-white rounded-full animate-welcome-bounce" style={{ animationDelay: '0.4s' }}></div>
          </div>
          <p className="text-white/70 mt-4 text-sm">Preparando tu dashboard...</p>
        </div>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-green-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Cargando...</p>
        </div>
      </div>
    );
  }

  if (showWelcome && welcomeUser) {
    return <WelcomeAnimation user={welcomeUser} />;
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-br from-blue-50 via-white to-green-50">
        <div className="relative">
          {authMode === 'login' ? (
            <Login 
              onLogin={handleLogin}
              onSwitchToRegister={() => setAuthMode('register')}
            />
          ) : (
            <Register 
              onRegister={handleRegister}
              onSwitchToLogin={() => setAuthMode('login')}
            />
          )}
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen transition-colors duration-300 ${
      darkMode 
        ? 'bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900' 
        : 'bg-gradient-to-br from-blue-50 via-white to-green-50'
    }`}>
      <div className={`shadow-lg border-b-4 transition-colors duration-300 ${
        darkMode 
          ? 'bg-gray-800 border-blue-400' 
          : 'bg-white border-blue-500'
      }`}>
        <div className="max-w-4xl mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3 flex-shrink-0">
              <div className="bg-blue-500 p-2 rounded-full">
                <Utensils className="w-5 h-5 sm:w-6 sm:h-6 text-white" />
              </div>
              <h1 className={`text-lg sm:text-2xl font-bold transition-colors duration-300 ${
                darkMode ? 'text-white' : 'text-gray-800'
              }`}>CaloriTracker</h1>
            </div>
            
            <div className="flex items-center space-x-2 sm:space-x-4">
              <div className={`hidden sm:block text-sm transition-colors duration-300 ${
                darkMode ? 'text-gray-300' : 'text-gray-600'
              }`}>
                Bienvenido, <span className="font-medium text-blue-500">{user.username}</span>
              </div>
              
              <DarkModeToggle />
              
              <button
                onClick={() => setCurrentView(currentView === 'dashboard' ? 'account' : 'dashboard')}
                className={`flex items-center space-x-1 sm:space-x-2 px-2 sm:px-4 py-2 rounded-lg transition-colors text-sm sm:text-base ${
                  currentView === 'account' 
                    ? 'bg-blue-500 text-white' 
                    : 'bg-gray-500 text-white hover:bg-gray-600'
                }`}
              >
                {currentView === 'dashboard' ? (
                  <>
                    <Settings className="w-4 h-4" />
                    <span className="hidden sm:inline">Cuenta</span>
                  </>
                ) : (
                  <>
                    <Target className="w-4 h-4" />
                    <span className="hidden sm:inline">Dashboard</span>
                  </>
                )}
              </button>
              
              <button
                onClick={handleLogout}
                className="flex items-center space-x-1 sm:space-x-2 bg-red-500 text-white px-2 sm:px-4 py-2 rounded-lg hover:bg-red-600 transition-colors text-sm sm:text-base"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:inline">Salir</span>
              </button>
            </div>
          </div>
          
          <div className={`sm:hidden mt-3 pt-3 border-t text-center text-sm transition-colors duration-300 ${
            darkMode ? 'border-gray-600 text-gray-300' : 'border-gray-200 text-gray-600'
          }`}>
            Bienvenido, <span className="font-medium text-blue-500">{user.username}</span>
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-6 py-8">
        {currentView === 'dashboard' ? (
          <>
            <div className="grid md:grid-cols-2 gap-6 mb-8">
              <div className="bg-gradient-to-r from-purple-500 to-pink-500 rounded-2xl p-6 text-white hover-lift transform hover:scale-105 transition-all duration-300">
                <div className="flex items-center space-x-3 mb-3">
                  <Heart className="w-6 h-6" />
                  <h3 className="font-semibold">Mensaje del Día</h3>
                </div>
                <p className="text-lg font-medium animate-welcome-pulse">
                  {motivationalMessages[currentMessage]}
                </p>
              </div>

              <div className="bg-gradient-to-r from-green-500 to-teal-500 rounded-2xl p-6 text-white hover-lift transform hover:scale-105 transition-all duration-300">
                <div className="flex items-center space-x-3 mb-3">
                  <Award className="w-6 h-6" />
                  <h3 className="font-semibold">Consejo Saludable</h3>
                </div>
                <p className="text-lg font-medium">
                  {healthTips[currentTip]}
                </p>
              </div>
            </div>

            <div className={`rounded-2xl shadow-xl p-4 sm:p-8 mb-8 border hover-lift transition-colors duration-300 ${
              darkMode 
                ? 'bg-gray-800 border-gray-700' 
                : 'bg-white border-gray-100'
            }`}>
              <div className="mb-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <h2 className={`text-xl sm:text-2xl font-bold flex items-center transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>
                    <Target className="w-5 h-5 sm:w-6 sm:h-6 mr-2 sm:mr-3 text-blue-500" />
                    Resumen del Día
                  </h2>
                  
                  <div className="flex flex-col sm:flex-row gap-3 sm:gap-3">
                    <div className="flex items-center space-x-2">
                      <label className={`text-xs sm:text-sm font-medium whitespace-nowrap transition-colors duration-300 ${
                        darkMode ? 'text-gray-300' : 'text-gray-600'
                      }`}>
                        Meta:
                      </label>
                      <input
                        type="number"
                        placeholder="2000"
                        value={dailyGoal}
                        onChange={handleGoalChange}
                        className={`w-20 sm:w-24 px-2 sm:px-3 py-2 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                          darkMode 
                            ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                            : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                        }`}
                      />
                      <span className={`text-xs sm:text-sm font-medium transition-colors duration-300 ${
                        darkMode ? 'text-gray-400' : 'text-gray-500'
                      }`}>
                        cal
                      </span>
                    </div>
                    
                    <button
                      onClick={resetDay}
                      className="px-3 sm:px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors text-sm font-medium flex items-center justify-center gap-1 whitespace-nowrap"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      <span className="hidden sm:inline">Reiniciar</span>
                      <span className="sm:hidden">Reset</span>
                    </button>
                  </div>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-6 mb-8">
                <div className="bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl p-6 text-white">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100 text-sm font-medium">Consumidas</p>
                      <p className="text-3xl font-bold">{totalCalories}</p>
                    </div>
                    <TrendingUp className="w-8 h-8 text-blue-200" />
                  </div>
                </div>

                <div className="bg-gradient-to-r from-green-500 to-green-600 rounded-xl p-6 text-white">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100 text-sm font-medium">Meta Diaria</p>
                      <p className="text-3xl font-bold">{dailyGoal}</p>
                    </div>
                    <Target className="w-8 h-8 text-green-200" />
                  </div>
                </div>

                <div className={`bg-gradient-to-r rounded-xl p-6 text-white ${
                  remainingCalories >= 0 
                    ? 'from-orange-500 to-orange-600' 
                    : 'from-red-500 to-red-600'
                }`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-orange-100 text-sm font-medium">
                        {remainingCalories >= 0 ? 'Restantes' : 'Excedente'}
                      </p>
                      <p className="text-3xl font-bold">{Math.abs(remainingCalories)}</p>
                    </div>
                    <Heart className="w-8 h-8 text-orange-200" />
                  </div>
                </div>
              </div>

              <div className="mb-6">
                <div className="flex justify-between items-center mb-2">
                  <span className={`text-sm font-medium transition-colors duration-300 ${
                    darkMode ? 'text-gray-300' : 'text-gray-600'
                  }`}>Progreso del día</span>
                  <span className={`text-sm font-medium transition-colors duration-300 ${
                    darkMode ? 'text-gray-300' : 'text-gray-600'
                  }`}>{progressPercentage.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-3">
                  <div 
                    className={`h-3 rounded-full transition-all duration-500 ${
                      progressPercentage <= 100 
                        ? 'bg-gradient-to-r from-green-400 to-green-600' 
                        : 'bg-gradient-to-r from-red-400 to-red-600'
                    }`}
                    style={{ width: `${Math.min(progressPercentage, 100)}%` }}
                  />
                </div>
              </div>
            </div>

            <div className={`rounded-2xl shadow-xl p-8 mb-8 border hover-lift transition-colors duration-300 ${
              darkMode 
                ? 'bg-gray-800 border-gray-700' 
                : 'bg-white border-gray-100'
            }`}>
              <div className="flex items-center justify-between mb-6">
                <h3 className={`text-xl font-bold transition-colors duration-300 ${
                  darkMode ? 'text-white' : 'text-gray-800'
                }`}>Agregar Alimento</h3>
                <button
                  onClick={() => setShowAddForm(!showAddForm)}
                  className="flex items-center space-x-2 bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors"
                >
                  <Plus className="w-5 h-5" />
                  <span>Nuevo</span>
                </button>
              </div>

              {showAddForm && (
                <div className={`rounded-xl p-6 border transition-colors duration-300 ${
                  darkMode 
                    ? 'bg-gray-700 border-gray-600' 
                    : 'bg-gray-50 border-gray-200'
                }`}>
                  <div className="grid md:grid-cols-2 gap-4 mb-4">
                    <input
                      type="text"
                      placeholder="Nombre del alimento"
                      value={newFood.name}
                      onChange={(e) => setNewFood({ ...newFood, name: e.target.value })}
                      className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                        darkMode 
                          ? 'bg-gray-600 border-gray-500 text-white placeholder-gray-400' 
                          : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                      }`}
                    />
                    <input
                      type="number"
                      placeholder="Calorías"
                      value={newFood.calories}
                      onChange={(e) => setNewFood({ ...newFood, calories: e.target.value })}
                      className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                        darkMode 
                          ? 'bg-gray-600 border-gray-500 text-white placeholder-gray-400' 
                          : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                      }`}
                    />
                  </div>
                  <div className="flex space-x-3">
                    <button
                      onClick={addFood}
                      className="px-6 py-3 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors font-medium"
                    >
                      Agregar
                    </button>
                    <button
                      onClick={() => setShowAddForm(false)}
                      className="px-6 py-3 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors font-medium"
                    >
                      Cancelar
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className={`rounded-2xl shadow-xl p-8 border hover-lift transition-colors duration-300 ${
              darkMode 
                ? 'bg-gray-800 border-gray-700' 
                : 'bg-white border-gray-100'
            }`}>
              <h3 className={`text-xl font-bold mb-6 transition-colors duration-300 ${
                darkMode ? 'text-white' : 'text-gray-800'
              }`}>Alimentos Consumidos Hoy</h3>
              
              {foods.length === 0 ? (
                <div className="text-center py-12">
                  <Utensils className={`w-16 h-16 mx-auto mb-4 ${
                    darkMode ? 'text-gray-500' : 'text-gray-300'
                  }`} />
                  <p className={`text-lg ${
                    darkMode ? 'text-gray-400' : 'text-gray-500'
                  }`}>No has agregado alimentos hoy</p>
                  <p className={`${
                    darkMode ? 'text-gray-500' : 'text-gray-400'
                  }`}>¡Empieza agregando tu primer alimento!</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {foods.map((food) => (
                    <div
                      key={food.id}
                      className={`flex items-center justify-between p-4 rounded-xl border hover:shadow-md transition-all duration-300 ${
                        darkMode 
                          ? 'bg-gray-700 border-gray-600 hover:bg-gray-600' 
                          : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                      }`}
                    >
                      <div className="flex items-center space-x-4">
                        <div className="bg-blue-500 p-2 rounded-full">
                          <Utensils className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <h4 className={`font-semibold transition-colors duration-300 ${
                            darkMode ? 'text-white' : 'text-gray-800'
                          }`}>{food.name}</h4>
                          <p className={`text-sm transition-colors duration-300 ${
                            darkMode ? 'text-gray-400' : 'text-gray-500'
                          }`}>Agregado a las {food.time}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <span className="text-lg font-bold text-green-500">{food.calories} cal</span>
                        <button
                          onClick={() => removeFood(food.id)}
                          className="group flex items-center justify-center w-8 h-8 bg-red-50 hover:bg-red-500 rounded-full transition-all duration-200 hover:scale-110 dark:bg-red-900/20 dark:hover:bg-red-500"
                          title="Eliminar alimento"
                        >
                          <svg 
                            className="w-4 h-4 text-red-500 group-hover:text-white transition-colors duration-200" 
                            fill="none" 
                            viewBox="0 0 24 24" 
                            stroke="currentColor"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          <AccountSettings 
            user={user}
            sessionToken={sessionToken}
            darkMode={darkMode}
            apiCall={apiCall}
          />
        )}
      </div>
    </div>
  );
};

export default CalorieTracker;