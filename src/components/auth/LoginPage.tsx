import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Heart, User, Stethoscope, Users, Shield, Lock } from 'lucide-react';

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialRole = searchParams.get('role') || 'patient';

  const [selectedRole, setSelectedRole] = useState(initialRole);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [showMFA, setShowMFA] = useState(false);

  const roles = [
    { value: 'patient', label: 'Patient', icon: User, color: 'pink' },
    { value: 'doctor', label: 'Doctor', icon: Stethoscope, color: 'blue' },
    { value: 'staff', label: 'Staff', icon: Users, color: 'purple' },
    { value: 'admin', label: 'Admin', icon: Shield, color: 'red' },
  ];

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!showMFA) {
      // First step: email and password
      setShowMFA(true);
    } else {
      // Second step: MFA verification
      // Redirect to appropriate dashboard based on role
      switch (selectedRole) {
        case 'patient':
          navigate('/patient/dashboard');
          break;
        case 'doctor':
          navigate('/doctor/dashboard');
          break;
        case 'staff':
          navigate('/staff/dashboard');
          break;
        case 'admin':
          navigate('/admin/dashboard');
          break;
        default:
          navigate('/patient/dashboard');
      }
    }
  };

  const selectedRoleData = roles.find(r => r.value === selectedRole);
  const RoleIcon = selectedRoleData?.icon || User;

  return (
    <div className="min-h-screen bg-gradient-to-br from-pink-50 to-white flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <Link to="/" className="flex items-center justify-center gap-2 mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-pink-400 to-pink-500 rounded-lg flex items-center justify-center">
            <Heart className="w-7 h-7 text-white" fill="white" />
          </div>
          <span className="text-pink-600 text-2xl">PinkHealth</span>
        </Link>

        {/* Login Card */}
        <div className="bg-white rounded-xl shadow-lg border border-gray-200 p-8">
          <h1 className="text-gray-900 text-center mb-6">
            {showMFA ? 'Verify Identity' : 'Welcome Back'}
          </h1>

          {!showMFA && (
            <>
              {/* Role Selection */}
              <div className="mb-6">
                <label className="block text-gray-700 mb-3">Select Portal</label>
                <div className="grid grid-cols-2 gap-3">
                  {roles.map((role) => {
                    const Icon = role.icon;
                    return (
                      <button
                        key={role.value}
                        type="button"
                        onClick={() => setSelectedRole(role.value)}
                        className={`p-4 rounded-lg border-2 transition-all ${
                          selectedRole === role.value
                            ? `border-${role.color}-500 bg-${role.color}-50`
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        <Icon
                          className={`w-6 h-6 mx-auto mb-2 ${
                            selectedRole === role.value
                              ? `text-${role.color}-600`
                              : 'text-gray-400'
                          }`}
                        />
                        <span
                          className={`text-sm ${
                            selectedRole === role.value
                              ? `text-${role.color}-600`
                              : 'text-gray-600'
                          }`}
                        >
                          {role.label}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-gray-700 mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                    placeholder="you@example.com"
                  />
                </div>

                <div>
                  <label htmlFor="password" className="block text-gray-700 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                    placeholder="••••••••"
                  />
                </div>

                <div className="flex items-center justify-between text-sm">
                  <label className="flex items-center gap-2 text-gray-600">
                    <input type="checkbox" className="rounded" />
                    Remember me
                  </label>
                  <Link to="/reset-password" className="text-pink-600 hover:text-pink-700">
                    Forgot password?
                  </Link>
                </div>

                <button
                  type="submit"
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Continue
                </button>
              </form>
            </>
          )}

          {showMFA && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-8 h-8 text-pink-600" />
                </div>
                <p className="text-gray-600">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>

              <div>
                <label htmlFor="totp" className="block text-gray-700 mb-2">
                  Authentication Code
                </label>
                <input
                  type="text"
                  id="totp"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  required
                  maxLength={6}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 text-center text-2xl tracking-widest"
                  placeholder="000000"
                />
              </div>

              <button
                type="submit"
                className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Verify & Login
              </button>

              <button
                type="button"
                onClick={() => setShowMFA(false)}
                className="w-full px-6 py-2 text-gray-600 hover:text-gray-800"
              >
                Back
              </button>
            </form>
          )}

          {/* Sign up link for patients */}
          {selectedRole === 'patient' && !showMFA && (
            <div className="mt-6 text-center text-sm text-gray-600">
              Don't have an account?{' '}
              <Link to="/signup" className="text-pink-600 hover:text-pink-700">
                Register as Patient
              </Link>
            </div>
          )}
        </div>

        {/* Security Notice */}
        <div className="mt-6 text-center text-sm text-gray-500">
          <p>🔒 Secured with end-to-end encryption</p>
        </div>
      </div>
    </div>
  );
}
