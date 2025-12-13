import { PublicLayout } from '../layouts/PublicLayout';
import { Link } from 'react-router-dom';
import { Shield, Calendar, FileText, Lock, Users, Clock, CheckCircle, Award } from 'lucide-react';

export function HomePage() {
  return (
    <PublicLayout>
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-pink-50 to-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto">
            <h1 className="text-gray-900 mb-6">
              Secure Care. Secure Data.
            </h1>
            <p className="text-gray-600 mb-8">
              Experience modern healthcare management with enterprise-grade security. 
              PinkHealth provides seamless access to your medical records, appointments, 
              and prescriptions while ensuring your data remains private and protected.
            </p>
            <div className="flex flex-wrap gap-4 justify-center">
              <Link
                to="/login"
                className="px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Login to Portal
              </Link>
              <Link
                to="/signup"
                className="px-6 py-3 bg-white text-pink-600 border-2 border-pink-500 rounded-lg hover:bg-pink-50 transition-colors"
              >
                Register as Patient
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-center text-gray-900 mb-12">
          Your Healthcare, Simplified & Secured
        </h2>
        <div className="grid md:grid-cols-3 gap-8">
          <div className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg transition-shadow">
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Calendar className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-2">Book Appointments</h3>
            <p className="text-gray-600">
              Schedule appointments with your preferred doctors at your convenience. 
              View real-time availability and receive instant confirmations.
            </p>
            <Link to="/login" className="text-pink-600 hover:text-pink-700 mt-4 inline-block">
              Get Started →
            </Link>
          </div>

          <div className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg transition-shadow">
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <FileText className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-2">Digital Prescriptions & MCs</h3>
            <p className="text-gray-600">
              Access your medical certificates and prescriptions online. 
              Download, print, or share securely with authorized parties.
            </p>
            <Link to="/login" className="text-pink-600 hover:text-pink-700 mt-4 inline-block">
              Learn More →
            </Link>
          </div>

          <div className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg transition-shadow">
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Lock className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-2">Enterprise Security</h3>
            <p className="text-gray-600">
              Your health data is encrypted end-to-end with military-grade security. 
              PDPA compliant with comprehensive audit trails.
            </p>
            <Link to="/about" className="text-pink-600 hover:text-pink-700 mt-4 inline-block">
              View Security →
            </Link>
          </div>
        </div>
      </section>

      {/* Portal Access Section */}
      <section className="bg-gray-50 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-center text-gray-900 mb-12">
            Access Your Portal
          </h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <Link
              to="/login?role=patient"
              className="bg-white p-6 rounded-xl border-2 border-gray-200 hover:border-pink-500 hover:shadow-lg transition-all text-center"
            >
              <div className="w-16 h-16 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Users className="w-8 h-8 text-pink-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Patient Portal</h3>
              <p className="text-gray-600 text-sm">
                View records, book appointments, access documents
              </p>
            </Link>

            <Link
              to="/login?role=doctor"
              className="bg-white p-6 rounded-xl border-2 border-gray-200 hover:border-blue-500 hover:shadow-lg transition-all text-center"
            >
              <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Users className="w-8 h-8 text-blue-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Doctor Portal</h3>
              <p className="text-gray-600 text-sm">
                Patient lookup, consultations, prescriptions, MCs
              </p>
            </Link>

            <Link
              to="/login?role=staff"
              className="bg-white p-6 rounded-xl border-2 border-gray-200 hover:border-purple-500 hover:shadow-lg transition-all text-center"
            >
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Users className="w-8 h-8 text-purple-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Staff Portal</h3>
              <p className="text-gray-600 text-sm">
                Registration, billing, appointment management
              </p>
            </Link>

            <Link
              to="/login?role=admin"
              className="bg-white p-6 rounded-xl border-2 border-gray-200 hover:border-red-500 hover:shadow-lg transition-all text-center"
            >
              <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Shield className="w-8 h-8 text-red-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Admin Portal</h3>
              <p className="text-gray-600 text-sm">
                User management, audit logs, system security
              </p>
            </Link>
          </div>
        </div>
      </section>

      {/* Trust & Security Section */}
      <section className="py-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-center text-gray-900 mb-12">
          Built on Trust & Security
        </h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-8 h-8 text-green-600" />
            </div>
            <h3 className="text-gray-900 mb-2">PDPA Compliant</h3>
            <p className="text-gray-600 text-sm">
              Full compliance with Singapore's Personal Data Protection Act
            </p>
          </div>

          <div className="text-center">
            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-8 h-8 text-blue-600" />
            </div>
            <h3 className="text-gray-900 mb-2">End-to-End Encryption</h3>
            <p className="text-gray-600 text-sm">
              Military-grade AES-256 encryption for all patient data
            </p>
          </div>

          <div className="text-center">
            <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Clock className="w-8 h-8 text-purple-600" />
            </div>
            <h3 className="text-gray-900 mb-2">Immutable Audit Logs</h3>
            <p className="text-gray-600 text-sm">
              Complete audit trail of all data access and modifications
            </p>
          </div>

          <div className="text-center">
            <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Award className="w-8 h-8 text-orange-600" />
            </div>
            <h3 className="text-gray-900 mb-2">ISO 27001 Certified</h3>
            <p className="text-gray-600 text-sm">
              International standard for information security management
            </p>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
