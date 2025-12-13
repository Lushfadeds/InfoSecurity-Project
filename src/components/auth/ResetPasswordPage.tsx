import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Heart, Mail, Lock, Check } from 'lucide-react';

export function ResetPasswordPage() {
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleSendOTP = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(2);
  };

  const handleVerifyOTP = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(3);
  };

  const handleResetPassword = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(4);
  };

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

        {/* Reset Password Card */}
        <div className="bg-white rounded-xl shadow-lg border border-gray-200 p-8">
          {/* Step 1: Enter Email */}
          {step === 1 && (
            <>
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Mail className="w-8 h-8 text-pink-600" />
                </div>
                <h1 className="text-gray-900 mb-2">Reset Password</h1>
                <p className="text-gray-600">
                  Enter your email address and we'll send you a verification code
                </p>
              </div>

              <form onSubmit={handleSendOTP} className="space-y-4">
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

                <button
                  type="submit"
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Send Verification Code
                </button>

                <Link
                  to="/login"
                  className="block w-full px-6 py-2 text-center text-gray-600 hover:text-gray-800"
                >
                  Back to Login
                </Link>
              </form>
            </>
          )}

          {/* Step 2: Verify OTP */}
          {step === 2 && (
            <>
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Mail className="w-8 h-8 text-pink-600" />
                </div>
                <h1 className="text-gray-900 mb-2">Verify Code</h1>
                <p className="text-gray-600">
                  We've sent a 6-digit code to
                </p>
                <p className="text-gray-900">{email}</p>
              </div>

              <form onSubmit={handleVerifyOTP} className="space-y-4">
                <div>
                  <label htmlFor="otp" className="block text-gray-700 mb-2">
                    Verification Code
                  </label>
                  <input
                    type="text"
                    id="otp"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    required
                    maxLength={6}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 text-center text-2xl tracking-widest"
                    placeholder="000000"
                  />
                </div>

                <p className="text-center text-sm text-gray-600">
                  Didn't receive the code?{' '}
                  <button
                    type="button"
                    onClick={() => setStep(1)}
                    className="text-pink-600 hover:text-pink-700"
                  >
                    Resend
                  </button>
                </p>

                <button
                  type="submit"
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Verify Code
                </button>

                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="w-full px-6 py-2 text-gray-600 hover:text-gray-800"
                >
                  Back
                </button>
              </form>
            </>
          )}

          {/* Step 3: Set New Password */}
          {step === 3 && (
            <>
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-8 h-8 text-pink-600" />
                </div>
                <h1 className="text-gray-900 mb-2">Create New Password</h1>
                <p className="text-gray-600">
                  Choose a strong password to secure your account
                </p>
              </div>

              <form onSubmit={handleResetPassword} className="space-y-4">
                <div>
                  <label htmlFor="newPassword" className="block text-gray-700 mb-2">
                    New Password
                  </label>
                  <input
                    type="password"
                    id="newPassword"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    minLength={8}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                    placeholder="••••••••"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Minimum 8 characters, including uppercase, lowercase, and numbers
                  </p>
                </div>

                <div>
                  <label htmlFor="confirmPassword" className="block text-gray-700 mb-2">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                    placeholder="••••••••"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Reset Password
                </button>
              </form>
            </>
          )}

          {/* Step 4: Success */}
          {step === 4 && (
            <>
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Check className="w-8 h-8 text-green-600" />
                </div>
                <h1 className="text-gray-900 mb-2">Password Reset Successful</h1>
                <p className="text-gray-600">
                  Your password has been successfully reset. You can now log in with your new password.
                </p>
              </div>

              <Link
                to="/login"
                className="block w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors text-center"
              >
                Continue to Login
              </Link>
            </>
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
