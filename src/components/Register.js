"use client";

import React, { useState } from 'react';
import { UserPlus, User, Lock, Mail, Eye, EyeOff } from 'lucide-react';

const Register = ({ onRegister, onSwitchToLogin }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [validationErrors, setValidationErrors] = useState([]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    if (error) setError('');
    if (success) setSuccess('');
    if (validationErrors.length > 0) setValidationErrors([]);
  };

  const validateForm = () => {
    if (!formData.username.trim()) {
      return 'El usuario es requerido';
    }
    if (formData.username.length < 3) {
      return 'El usuario debe tener al menos 3 caracteres';
    }
    if (!formData.email.trim()) {
      return 'El email es requerido';
    }
    if (!/\S+@\S+\.\S+/.test(formData.email)) {
      return 'El email no es válido';
    }
    if (!formData.password) {
      return 'La contraseña es requerida';
    }
    if (formData.password.length < 6) {
      return 'La contraseña debe tener al menos 6 caracteres';
    }
    if (formData.password !== formData.confirmPassword) {
      return 'Las contraseñas no coinciden';
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setSuccess('');
    setValidationErrors([]);

    const clientValidationErrors = validateForm();
    if (clientValidationErrors) {
      setError(clientValidationErrors);
      setIsLoading(false);
      return;
    }

    const result = await onRegister({
      username: formData.username,
      email: formData.email,
      password: formData.password
    });

    if (result.success) {
      setSuccess('¡Registro exitoso! Iniciando sesión...');
    } else {
      const errorMessage = result.error || 'Error al crear la cuenta';
      
      if (errorMessage.includes('.') && (errorMessage.includes('mayúscula') || errorMessage.includes('minúscula') || errorMessage.includes('número') || errorMessage.includes('carácter especial'))) {
        const errors = errorMessage.split('.').filter(err => err.trim().length > 0);
        setValidationErrors(errors);
      } else {
        setError(errorMessage);
      }
    }
    
    setIsLoading(false);
  };

  return (
    <div className="w-full max-w-md mx-auto bg-white rounded-2xl shadow-xl p-8 border border-gray-100">
      <div className="text-center mb-8">
        <div className="bg-green-500 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
          <UserPlus className="w-8 h-8 text-white" />
        </div>
        <h2 className="text-2xl font-bold text-gray-800">Crear Cuenta</h2>
        <p className="text-gray-600">Únete a CaloriTracker</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Errores de Validación de Password */}
        {validationErrors.length > 0 && (
          <div className="bg-amber-50 border-l-4 border-amber-400 p-4 rounded-md message-enter">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-amber-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-amber-800">
                  Requisitos de contraseña no cumplidos:
                </h3>
                <div className="mt-2 text-sm text-amber-700">
                  <ul className="list-disc list-inside space-y-1">
                    {validationErrors.map((error, index) => (
                      <li key={index} className="form-field-enter">{error.trim()}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Mensaje de Error General */}
        {error && (
          <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded-md message-enter">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-red-800">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Mensaje de Éxito */}
        {success && (
          <div className="bg-green-50 border-l-4 border-green-400 p-4 rounded-md message-enter success-bounce">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-green-800">{success}</p>
              </div>
            </div>
          </div>
        )}

        <div className="form-field-enter">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Usuario
          </label>
          <div className="relative">
            <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
              placeholder="Elige un nombre de usuario"
              disabled={isLoading}
            />
          </div>
        </div>

        <div className="form-field-enter">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Email
          </label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
              placeholder="tu@email.com"
              disabled={isLoading}
            />
          </div>
        </div>

        {/* Indicador de Fuerza de Contraseña */}
        <div className="form-field-enter">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Contraseña
          </label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type={showPassword ? "text" : "password"}
              name="password"
              value={formData.password}
              onChange={handleChange}
              className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
              placeholder="Mínimo 8 caracteres"
              disabled={isLoading}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors duration-200"
              disabled={isLoading}
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
          
          {/* Indicadores de Fuerza */}
          {formData.password && (
            <div className="mt-2 space-y-1 animate-welcome-fade-in-up">
              <div className="text-xs text-gray-600">Requisitos de contraseña:</div>
              <div className="grid grid-cols-2 gap-1 text-xs">
                <div className={`flex items-center transition-colors duration-300 ${formData.password.length >= 8 ? 'text-green-600' : 'text-gray-400'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 transition-all duration-300 ${formData.password.length >= 8 ? 'bg-green-500 animate-welcome-pulse' : 'bg-gray-300'}`}></div>
                  8+ caracteres
                </div>
                <div className={`flex items-center transition-colors duration-300 ${/[A-Z]/.test(formData.password) ? 'text-green-600' : 'text-gray-400'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 transition-all duration-300 ${/[A-Z]/.test(formData.password) ? 'bg-green-500 animate-welcome-pulse' : 'bg-gray-300'}`}></div>
                  Mayúscula
                </div>
                <div className={`flex items-center transition-colors duration-300 ${/[a-z]/.test(formData.password) ? 'text-green-600' : 'text-gray-400'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 transition-all duration-300 ${/[a-z]/.test(formData.password) ? 'bg-green-500 animate-welcome-pulse' : 'bg-gray-300'}`}></div>
                  Minúscula
                </div>
                <div className={`flex items-center transition-colors duration-300 ${/[0-9]/.test(formData.password) ? 'text-green-600' : 'text-gray-400'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 transition-all duration-300 ${/[0-9]/.test(formData.password) ? 'bg-green-500 animate-welcome-pulse' : 'bg-gray-300'}`}></div>
                  Número
                </div>
                <div className={`flex items-center transition-colors duration-300 ${/[^A-Za-z0-9]/.test(formData.password) ? 'text-green-600' : 'text-gray-400'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 transition-all duration-300 ${/[^A-Za-z0-9]/.test(formData.password) ? 'bg-green-500 animate-welcome-pulse' : 'bg-gray-300'}`}></div>
                  Carácter especial
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="form-field-enter">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Confirmar Contraseña
          </label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type={showConfirmPassword ? "text" : "password"}
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
              placeholder="Repite tu contraseña"
              disabled={isLoading}
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors duration-200"
              disabled={isLoading}
            >
              {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full bg-green-500 text-white py-3 rounded-lg hover:bg-green-600 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
              Creando cuenta...
            </div>
          ) : (
            'Crear Cuenta'
          )}
        </button>
      </form>

      <div className="mt-6 text-center">
        <p className="text-gray-600">
          ¿Ya tienes cuenta?{' '}
          <button
            onClick={onSwitchToLogin}
            className="text-green-500 hover:text-green-600 font-medium"
            disabled={isLoading}
          >
            Inicia sesión aquí
          </button>
        </p>
      </div>
    </div>
  );
};

export default Register;