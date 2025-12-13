import { Link } from 'react-router-dom';
import { Heart, Menu, X } from 'lucide-react';
import { useState } from 'react';

interface PublicLayoutProps {
  children: React.ReactNode;
}

export function PublicLayout({ children }: PublicLayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2">
              <div className="w-10 h-10 bg-gradient-to-br from-pink-400 to-pink-500 rounded-lg flex items-center justify-center">
                <Heart className="w-6 h-6 text-white" fill="white" />
              </div>
              <span className="text-pink-600">PinkHealth</span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-6">
              <Link to="/" className="text-gray-700 hover:text-pink-600 transition-colors">
                Home
              </Link>
              <Link to="/about" className="text-gray-700 hover:text-pink-600 transition-colors">
                About Us
              </Link>
              <Link to="/faq" className="text-gray-700 hover:text-pink-600 transition-colors">
                FAQ
              </Link>
              <Link to="/contact" className="text-gray-700 hover:text-pink-600 transition-colors">
                Contact
              </Link>
              <Link to="/announcements" className="text-gray-700 hover:text-pink-600 transition-colors">
                Announcements
              </Link>
              <Link
                to="/login"
                className="px-4 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Login
              </Link>
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2"
            >
              {mobileMenuOpen ? <X /> : <Menu />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200 bg-white">
            <div className="px-4 py-2 space-y-1">
              <Link
                to="/"
                className="block px-3 py-2 text-gray-700 hover:bg-pink-50 rounded-lg"
                onClick={() => setMobileMenuOpen(false)}
              >
                Home
              </Link>
              <Link
                to="/about"
                className="block px-3 py-2 text-gray-700 hover:bg-pink-50 rounded-lg"
                onClick={() => setMobileMenuOpen(false)}
              >
                About Us
              </Link>
              <Link
                to="/faq"
                className="block px-3 py-2 text-gray-700 hover:bg-pink-50 rounded-lg"
                onClick={() => setMobileMenuOpen(false)}
              >
                FAQ
              </Link>
              <Link
                to="/contact"
                className="block px-3 py-2 text-gray-700 hover:bg-pink-50 rounded-lg"
                onClick={() => setMobileMenuOpen(false)}
              >
                Contact
              </Link>
              <Link
                to="/announcements"
                className="block px-3 py-2 text-gray-700 hover:bg-pink-50 rounded-lg"
                onClick={() => setMobileMenuOpen(false)}
              >
                Announcements
              </Link>
              <Link
                to="/login"
                className="block px-3 py-2 bg-pink-500 text-white rounded-lg text-center"
                onClick={() => setMobileMenuOpen(false)}
              >
                Login
              </Link>
            </div>
          </div>
        )}
      </nav>

      {/* Main Content */}
      <main>{children}</main>

      {/* Footer */}
      <footer className="bg-gray-50 border-t border-gray-200 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 bg-gradient-to-br from-pink-400 to-pink-500 rounded-lg flex items-center justify-center">
                  <Heart className="w-5 h-5 text-white" fill="white" />
                </div>
                <span className="text-pink-600">PinkHealth</span>
              </div>
              <p className="text-gray-600 text-sm">
                Secure Care. Secure Data.
              </p>
            </div>
            <div>
              <h3 className="mb-4 text-gray-900">Quick Links</h3>
              <div className="space-y-2">
                <Link to="/" className="block text-sm text-gray-600 hover:text-pink-600">
                  Home
                </Link>
                <Link to="/about" className="block text-sm text-gray-600 hover:text-pink-600">
                  About Us
                </Link>
                <Link to="/faq" className="block text-sm text-gray-600 hover:text-pink-600">
                  FAQ
                </Link>
              </div>
            </div>
            <div>
              <h3 className="mb-4 text-gray-900">Portals</h3>
              <div className="space-y-2">
                <Link to="/login?role=patient" className="block text-sm text-gray-600 hover:text-pink-600">
                  Patient Portal
                </Link>
                <Link to="/login?role=doctor" className="block text-sm text-gray-600 hover:text-pink-600">
                  Doctor Portal
                </Link>
                <Link to="/login?role=staff" className="block text-sm text-gray-600 hover:text-pink-600">
                  Staff Portal
                </Link>
              </div>
            </div>
            <div>
              <h3 className="mb-4 text-gray-900">Contact</h3>
              <div className="space-y-2 text-sm text-gray-600">
                <p>123 Medical Centre Road</p>
                <p>Singapore 123456</p>
                <p>Tel: +65 6123 4567</p>
                <p>Email: info@pinkhealth.sg</p>
              </div>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-gray-200 text-center text-sm text-gray-600">
            <p>&copy; 2025 PinkHealth. All rights reserved. PDPA Compliant | ISO 27001 Certified</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
