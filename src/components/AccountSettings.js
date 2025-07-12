"use client";

import React, { useState, useEffect } from 'react';
import { User, Shield, Clock, Key } from 'lucide-react';

const AccountSettings = ({ user, sessionToken, darkMode, apiCall }) => {
  const [accountData, setAccountData] = useState(null);
  const [securityLogs, setSecurityLogs] = useState([]);
  const [showPasswordChange, setShowPasswordChange] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  useEffect(() => {
    if (user && sessionToken) {
      loadAccountData();
      loadSecurityLogs();
    }
  }, [user, sessionToken]);

  const loadAccountData = async () => {
    try {
      const data = await apiCall('account?action=info');
      setAccountData(data.account);
    } catch (error) {
      console.error('Failed to load account data:', error);
    }
  };

  const loadSecurityLogs = async () => {
    try {
      const data = await apiCall('account?action=logs');
      setSecurityLogs(data.logs);
    } catch (error) {
      console.error('Failed to load security logs:', error);
    }
  };

  const changePassword = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      alert('Las nuevas contraseñas no coinciden');
      return;
    }

    try {
      await apiCall('account?action=password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: passwordForm.currentPassword,
          new_password: passwordForm.newPassword
        })
      });

      alert('Contraseña cambiada exitosamente');
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setShowPasswordChange(false);
    } catch (error) {
      alert('Error al cambiar contraseña: ' + error.message);
    }
  };

  return (
    <div className="space-y-8">
      <div className={`rounded-2xl shadow-xl p-8 border hover-lift transition-colors duration-300 ${
        darkMode 
          ? 'bg-gray-800 border-gray-700' 
          : 'bg-white border-gray-100'
      }`}>
        <div className="flex items-center mb-6">
          <User className="w-6 h-6 mr-3 text-blue-500" />
          <h2 className={`text-2xl font-bold transition-colors duration-300 ${
            darkMode ? 'text-white' : 'text-gray-800'
          }`}>Información de la Cuenta</h2>
        </div>

        {accountData ? (
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <label className={`block text-sm font-medium mb-2 transition-colors duration-300 ${
                darkMode ? 'text-gray-300' : 'text-gray-700'
              }`}>Usuario</label>
              <p className={`text-lg font-semibold transition-colors duration-300 ${
                darkMode ? 'text-white' : 'text-gray-800'
              }`}>{accountData.username}</p>
            </div>
            <div>
              <label className={`block text-sm font-medium mb-2 transition-colors duration-300 ${
                darkMode ? 'text-gray-300' : 'text-gray-700'
              }`}>Email</label>
              <p className={`text-lg font-semibold transition-colors duration-300 ${
                darkMode ? 'text-white' : 'text-gray-800'
              }`}>{accountData.email}</p>
            </div>
            <div>
              <label className={`block text-sm font-medium mb-2 transition-colors duration-300 ${
                darkMode ? 'text-gray-300' : 'text-gray-700'
              }`}>Cuenta creada</label>
              <p className={`text-lg font-semibold transition-colors duration-300 ${
                darkMode ? 'text-white' : 'text-gray-800'
              }`}>{new Date(accountData.created_at).toLocaleDateString()}</p>
            </div>
            <div>
              <label className={`block text-sm font-medium mb-2 transition-colors duration-300 ${
                darkMode ? 'text-gray-300' : 'text-gray-700'
              }`}>Meta diaria actual</label>
              <p className={`text-lg font-semibold text-green-500`}>{accountData.daily_calorie_goal} calorías</p>
            </div>
          </div>
        ) : (
          <div className="text-center py-8">
            <div className={`animate-spin rounded-full h-8 w-8 border-b-2 mx-auto mb-4 ${
              darkMode ? 'border-blue-400' : 'border-blue-500'
            }`}></div>
            <p className={darkMode ? 'text-gray-300' : 'text-gray-600'}>Cargando información...</p>
          </div>
        )}
      </div>

      <div className={`rounded-2xl shadow-xl p-8 border hover-lift transition-colors duration-300 ${
        darkMode 
          ? 'bg-gray-800 border-gray-700' 
          : 'bg-white border-gray-100'
      }`}>
        <div className="flex items-center mb-6">
          <Key className="w-6 h-6 mr-3 text-blue-500" />
          <h3 className={`text-xl font-bold transition-colors duration-300 ${
            darkMode ? 'text-white' : 'text-gray-800'
          }`}>Seguridad y Privacidad</h3>
        </div>

        <div className="relative">
          <div className="grid md:grid-cols-2 gap-6">
            <div className={`p-6 rounded-xl border transition-colors duration-300 ${
              darkMode 
                ? 'bg-gray-700 border-gray-600' 
                : 'bg-gray-50 border-gray-200'
            }`}>
              <div className="flex items-center mb-4">
                <div className="p-2 rounded-full bg-blue-100 dark:bg-blue-900/30 mr-3">
                  <Key className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h4 className={`font-semibold transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>Contraseña</h4>
                  <p className={`text-sm transition-colors duration-300 ${
                    darkMode ? 'text-gray-400' : 'text-gray-500'
                  }`}>Actualiza tu contraseña de acceso</p>
                </div>
              </div>
              <button
                onClick={() => setShowPasswordChange(!showPasswordChange)}
                className="w-full bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors text-sm font-medium"
              >
                {showPasswordChange ? 'Cancelar' : 'Cambiar Contraseña'}
              </button>
            </div>

            <div className={`p-6 rounded-xl border transition-all duration-500 ${
              showPasswordChange ? 'opacity-30 blur-sm scale-95' : 'opacity-100 blur-none scale-100'
            } ${
              darkMode 
                ? 'bg-gray-700 border-gray-600' 
                : 'bg-gray-50 border-gray-200'
            }`}>
              <div className="flex items-center mb-4">
                <div className="p-2 rounded-full bg-green-100 dark:bg-green-900/30 mr-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <h4 className={`font-semibold transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>Sesión Actual</h4>
                  <p className={`text-sm transition-colors duration-300 ${
                    darkMode ? 'text-gray-400' : 'text-gray-500'
                  }`}>Información de tu sesión activa</p>
                </div>
              </div>
              <div className="space-y-2 text-sm">
                <div className={`transition-colors duration-300 ${
                  darkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  <span className="font-medium">Estado:</span> 
                  <span className="ml-2 text-green-500">🟢 Activa</span>
                </div>
                <div className={`transition-colors duration-300 ${
                  darkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  <span className="font-medium">Dispositivo:</span> 
                  <span className="ml-2">🖥️ Web Browser</span>
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-xl border transition-all duration-500 ${
              showPasswordChange ? 'opacity-30 blur-sm scale-95' : 'opacity-100 blur-none scale-100'
            } ${
              darkMode 
                ? 'bg-gray-700 border-gray-600' 
                : 'bg-gray-50 border-gray-200'
            }`}>
              <div className="flex items-center mb-4">
                <div className="p-2 rounded-full bg-orange-100 dark:bg-orange-900/30 mr-3">
                  <Clock className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                </div>
                <div>
                  <h4 className={`font-semibold transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>Intentos de Acceso</h4>
                  <p className={`text-sm transition-colors duration-300 ${
                    darkMode ? 'text-gray-400' : 'text-gray-500'
                  }`}>Intentos fallidos recientes</p>
                </div>
              </div>
              <div className="space-y-2 text-sm">
                <div className={`transition-colors duration-300 ${
                  darkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  <span className="font-medium">Fallidos:</span> 
                  <span className="ml-2">{accountData?.failed_login_attempts || 0}</span>
                </div>
                <div className={`transition-colors duration-300 ${
                  darkMode ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  <span className="font-medium">Último:</span> 
                  <span className="ml-2">
                    {accountData?.last_failed_login 
                      ? new Date(accountData.last_failed_login).toLocaleDateString('es-ES')
                      : 'Ninguno'
                    }
                  </span>
                </div>
              </div>
            </div>

            <div className={`p-6 rounded-xl border transition-all duration-500 ${
              showPasswordChange ? 'opacity-30 blur-sm scale-95' : 'opacity-100 blur-none scale-100'
            } ${
              darkMode 
                ? 'bg-gray-700 border-gray-600' 
                : 'bg-gray-50 border-gray-200'
            }`}>
              <div className="flex items-center mb-4">
                <div className="p-2 rounded-full bg-purple-100 dark:bg-purple-900/30 mr-3">
                  <User className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h4 className={`font-semibold transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>Privacidad</h4>
                  <p className={`text-sm transition-colors duration-300 ${
                    darkMode ? 'text-gray-400' : 'text-gray-500'
                  }`}>Configuración de datos personales</p>
                </div>
              </div>
              <button
                className="w-full bg-purple-500 text-white px-4 py-2 rounded-lg hover:bg-purple-600 transition-colors text-sm font-medium"
                onClick={() => alert('Funcionalidad próximamente disponible')}
              >
                Gestionar Datos
              </button>
            </div>
          </div>

          {showPasswordChange && (
            <div className={`absolute inset-0 z-10 flex items-center justify-center p-4 animate-welcome-fade-in-up`}>
              <div className={`w-full max-w-md rounded-2xl shadow-2xl border-2 p-6 backdrop-blur-sm ${
                darkMode 
                  ? 'bg-gray-800/95 border-gray-600 shadow-black/50' 
                  : 'bg-white/95 border-gray-200 shadow-gray-500/25'
              }`}>
                <div className="flex items-center justify-between mb-6">
                  <h5 className={`text-lg font-bold transition-colors duration-300 ${
                    darkMode ? 'text-white' : 'text-gray-800'
                  }`}>🔐 Cambiar Contraseña</h5>
                  <button
                    onClick={() => setShowPasswordChange(false)}
                    className={`p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors ${
                      darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    ✕
                  </button>
                </div>
                
                <div className="space-y-4">
                  <input
                    type="password"
                    placeholder="Contraseña actual"
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, currentPassword: e.target.value})}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                      darkMode 
                        ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                        : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                    }`}
                  />
                  <input
                    type="password"
                    placeholder="Nueva contraseña"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                      darkMode 
                        ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                        : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                    }`}
                  />
                  <input
                    type="password"
                    placeholder="Confirmar nueva contraseña"
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-medium transition-colors duration-300 ${
                      darkMode 
                        ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                        : 'bg-white border-gray-300 text-gray-800 placeholder-gray-500'
                    }`}
                  />
                  <div className="flex space-x-3 pt-2">
                    <button
                      onClick={changePassword}
                      className="flex-1 py-3 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors font-medium"
                    >
                      ✅ Actualizar
                    </button>
                    <button
                      onClick={() => setShowPasswordChange(false)}
                      className="flex-1 py-3 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors font-medium"
                    >
                      ❌ Cancelar
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className={`rounded-2xl shadow-xl p-8 border hover-lift transition-colors duration-300 ${
        darkMode 
          ? 'bg-gray-800 border-gray-700' 
          : 'bg-white border-gray-100'
      }`}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center">
            <Shield className="w-6 h-6 mr-3 text-blue-500" />
            <h3 className={`text-xl font-bold transition-colors duration-300 ${
              darkMode ? 'text-white' : 'text-gray-800'
            }`}>Actividad Reciente</h3>
          </div>
          {securityLogs.length > 0 && (
            <span className={`text-sm px-3 py-1 rounded-full transition-colors duration-300 ${
              darkMode 
                ? 'bg-gray-700 text-gray-300' 
                : 'bg-gray-100 text-gray-600'
            }`}>
              {securityLogs.length} {securityLogs.length === 1 ? 'registro' : 'registros'}
            </span>
          )}
        </div>

        {securityLogs.length > 0 ? (
          <div className={`space-y-3 max-h-96 overflow-y-auto pr-2 ${
            darkMode ? 'custom-scrollbar-dark' : 'custom-scrollbar-light'
          }`}>
            {securityLogs.map((log, index) => (
              <div
                key={index}
                className={`flex items-center justify-between p-4 rounded-xl border transition-all duration-300 hover:scale-[1.02] ${
                  darkMode 
                    ? 'bg-gray-700 border-gray-600 hover:bg-gray-650' 
                    : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                }`}
              >
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-full transition-all duration-300 ${
                    log.action.includes('SUCCESS') || log.action.includes('LOGOUT') 
                      ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' 
                      : log.action.includes('FAILED') || log.action.includes('LOCKED')
                      ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400'
                      : 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'
                  }`}>
                    <Clock className="w-4 h-4" />
                  </div>
                  <div className="flex-1">
                    <h4 className={`font-semibold transition-colors duration-300 ${
                      darkMode ? 'text-white' : 'text-gray-800'
                    }`}>
                      {log.action.replace(/_/g, ' ').toLowerCase().replace(/^\w/, c => c.toUpperCase())}
                    </h4>
                    <p className={`text-sm transition-colors duration-300 ${
                      darkMode ? 'text-gray-400' : 'text-gray-500'
                    }`}>
                      {new Date(log.created_at).toLocaleString('es-ES', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      })} • IP: {log.ip_address}
                    </p>
                  </div>
                </div>
                <div className={`text-lg font-bold transition-colors duration-300 ${
                  log.action.includes('SUCCESS') || log.action.includes('LOGOUT') 
                    ? 'text-green-500' 
                    : log.action.includes('FAILED') || log.action.includes('LOCKED')
                    ? 'text-red-500'
                    : 'text-blue-500'
                }`}>
                  {log.action.includes('SUCCESS') ? '✓' : 
                   log.action.includes('FAILED') || log.action.includes('LOCKED') ? '✗' : 'ℹ'}
                </div>
              </div>
            ))}
            
            {securityLogs.length === 15 && (
              <div className={`text-center pt-4 border-t transition-colors duration-300 ${
                darkMode ? 'border-gray-600' : 'border-gray-200'
              }`}>
                <p className={`text-sm transition-colors duration-300 ${
                  darkMode ? 'text-gray-400' : 'text-gray-500'
                }`}>
                  📋 Mostrando los últimos 15 registros de actividad
                </p>
              </div>
            )}
            
            {securityLogs.length > 6 && (
              <div className={`text-center pt-2 transition-colors duration-300 ${
                darkMode ? 'text-gray-500' : 'text-gray-400'
              }`}>
                <p className="text-xs">⬇️ Desplázate para ver más actividad</p>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-12">
            <Shield className={`w-16 h-16 mx-auto mb-4 transition-colors duration-300 ${
              darkMode ? 'text-gray-500' : 'text-gray-300'
            }`} />
            <p className={`text-lg mb-2 transition-colors duration-300 ${
              darkMode ? 'text-gray-400' : 'text-gray-500'
            }`}>No hay actividad registrada</p>
            <p className={`text-sm transition-colors duration-300 ${
              darkMode ? 'text-gray-500' : 'text-gray-400'
            }`}>Los registros aparecerán aquí cuando realices acciones en tu cuenta</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AccountSettings;