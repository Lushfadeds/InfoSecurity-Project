import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Heart, Check } from 'lucide-react';

export function SignupPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    fullName: '',
    nric: '',
    phone: '',
    email: '',
    password: '',
    confirmPassword: '',
    otp: '',
    acceptTerms: false,
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value,
    });
  };

  const handleStep1Submit = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(2);
  };

  const handleStep2Submit = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(3);
  };

  const handleFinalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Account created successfully
    navigate('/login?role=patient');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-pink-50 to-white flex items-center justify-center p-4">
      <div className="w-full max-w-2xl">
        {/* Logo */}
        <Link to="/" className="flex items-center justify-center gap-2 mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-pink-400 to-pink-500 rounded-lg flex items-center justify-center">
            <Heart className="w-7 h-7 text-white" fill="white" />
          </div>
          <span className="text-pink-600 text-2xl">PinkHealth</span>
        </Link>

        {/* Signup Card */}
        <div className="bg-white rounded-xl shadow-lg border border-gray-200 p-8">
          <h1 className="text-gray-900 text-center mb-2">Create Patient Account</h1>
          <p className="text-gray-600 text-center mb-8">
            Join PinkHealth for secure access to your medical records
          </p>

          {/* Progress Steps */}
          <div className="flex items-center justify-center mb-8">
            <div className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 1 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}
              >
                {step > 1 ? <Check className="w-5 h-5" /> : '1'}
              </div>
              <span className="text-sm text-gray-600 hidden sm:inline">Personal Info</span>
            </div>
            <div className={`w-16 h-0.5 mx-2 ${step >= 2 ? 'bg-pink-500' : 'bg-gray-200'}`}></div>
            <div className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 2 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}
              >
                {step > 2 ? <Check className="w-5 h-5" /> : '2'}
              </div>
              <span className="text-sm text-gray-600 hidden sm:inline">Account Details</span>
            </div>
            <div className={`w-16 h-0.5 mx-2 ${step >= 3 ? 'bg-pink-500' : 'bg-gray-200'}`}></div>
            <div className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 3 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}
              >
                3
              </div>
              <span className="text-sm text-gray-600 hidden sm:inline">Verification</span>
            </div>
          </div>

          {/* Step 1: Personal Information */}
          {step === 1 && (
            <form onSubmit={handleStep1Submit} className="space-y-4">
              <div>
                <label htmlFor="fullName" className="block text-gray-700 mb-2">
                  Full Name (as per NRIC) *
                </label>
                <input
                  type="text"
                  id="fullName"
                  name="fullName"
                  value={formData.fullName}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  placeholder="John Doe"
                />
              </div>

              <div>
                <label htmlFor="nric" className="block text-gray-700 mb-2">
                  NRIC / FIN *
                </label>
                <input
                  type="text"
                  id="nric"
                  name="nric"
                  value={formData.nric}
                  onChange={handleChange}
                  required
                  maxLength={9}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  placeholder="S1234567A"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Your NRIC will be encrypted and masked after registration
                </p>
              </div>

              <div>
                <label htmlFor="phone" className="block text-gray-700 mb-2">
                  Mobile Number *
                </label>
                <input
                  type="tel"
                  id="phone"
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  placeholder="+65 9123 4567"
                />
              </div>

              <button
                type="submit"
                className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Continue
              </button>
            </form>
          )}

          {/* Step 2: Account Details */}
          {step === 2 && (
            <form onSubmit={handleStep2Submit} className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-gray-700 mb-2">
                  Email Address *
                </label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  placeholder="john@example.com"
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-gray-700 mb-2">
                  Password *
                </label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
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
                  Confirm Password *
                </label>
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  placeholder="••••••••"
                />
              </div>

              <div className="flex items-start gap-2">
                <input
                  type="checkbox"
                  id="acceptTerms"
                  name="acceptTerms"
                  checked={formData.acceptTerms}
                  onChange={handleChange}
                  required
                  className="mt-1"
                />
                <label htmlFor="acceptTerms" className="text-sm text-gray-600">
                  I agree to the{' '}
                  <a href="#" className="text-pink-600 hover:text-pink-700">
                    Terms of Service
                  </a>{' '}
                  and{' '}
                  <a href="#" className="text-pink-600 hover:text-pink-700">
                    Privacy Policy
                  </a>
                  , and consent to the collection and processing of my personal health data in
                  accordance with PDPA.
                </label>
              </div>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="flex-1 px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Continue
                </button>
              </div>
            </form>
          )}

          {/* Step 3: OTP Verification */}
          {step === 3 && (
            <form onSubmit={handleFinalSubmit} className="space-y-4">
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Heart className="w-8 h-8 text-pink-600" fill="currentColor" />
                </div>
                <p className="text-gray-600">
                  We've sent a 6-digit verification code to
                </p>
                <p className="text-gray-900">{formData.phone}</p>
                <p className="text-gray-900">{formData.email}</p>
              </div>

              <div>
                <label htmlFor="otp" className="block text-gray-700 mb-2">
                  Verification Code
                </label>
                <input
                  type="text"
                  id="otp"
                  name="otp"
                  value={formData.otp}
                  onChange={handleChange}
                  required
                  maxLength={6}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 text-center text-2xl tracking-widest"
                  placeholder="000000"
                />
              </div>

              <p className="text-center text-sm text-gray-600">
                Didn't receive the code?{' '}
                <button type="button" className="text-pink-600 hover:text-pink-700">
                  Resend OTP
                </button>
              </p>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="flex-1 px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                >
                  Create Account
                </button>
              </div>
            </form>
          )}

          {/* Login link */}
          <div className="mt-6 text-center text-sm text-gray-600">
            Already have an account?{' '}
            <Link to="/login?role=patient" className="text-pink-600 hover:text-pink-700">
              Login
            </Link>
          </div>
        </div>

        {/* Security Notice */}
        <div className="mt-6 text-center text-sm text-gray-500">
          <p>🔒 Your data is encrypted and PDPA compliant</p>
        </div>
      </div>
    </div>
  );
}
