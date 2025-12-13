import { Link, useNavigate } from 'react-router-dom';
import { Heart, Menu, X, LogOut, Shield, User, Bell } from 'lucide-react';
import { useState } from 'react';

interface DashboardLayoutProps {
  children: React.ReactNode;
  role: 'patient' | 'doctor' | 'staff' | 'pharmacy' | 'admin';
  sidebarItems: {
    icon: React.ReactNode;
    label: string;
    path: string;
  }[];
  userName?: string;
}

export function DashboardLayout({ children, role, sidebarItems, userName = 'User' }: DashboardLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useNavigate();

  const roleColors = {
    patient: 'bg-pink-500',
    doctor: 'bg-blue-500',
    staff: 'bg-purple-500',
    pharmacy: 'bg-green-500',
    admin: 'bg-red-500',
  };

  const roleLabels = {
    patient: 'Patient Portal',
    doctor: 'Doctor Portal',
    staff: 'Staff Portal',
    pharmacy: 'Pharmacy Portal',
    admin: 'Admin Portal',
  };

  const handleLogout = () => {
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Navigation Bar */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo and Menu Toggle */}
            <div className="flex items-center gap-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden p-2 hover:bg-gray-100 rounded-lg"
              >
                {sidebarOpen ? <X /> : <Menu />}
              </button>
              <Link to="/" className="flex items-center gap-2">
                <div className="w-10 h-10 bg-gradient-to-br from-pink-400 to-pink-500 rounded-lg flex items-center justify-center">
                  <Heart className="w-6 h-6 text-white" fill="white" />
                </div>
                <span className="text-pink-600">PinkHealth</span>
              </Link>
              <span className="text-gray-400 hidden md:block">|</span>
              <span className="text-gray-600 hidden md:block">{roleLabels[role]}</span>
            </div>

            {/* Right side actions */}
            <div className="flex items-center gap-2">
              <button className="p-2 hover:bg-gray-100 rounded-lg relative">
                <Bell className="w-5 h-5 text-gray-600" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-pink-500 rounded-full"></span>
              </button>
              <div className="flex items-center gap-2 px-3 py-2 hover:bg-gray-100 rounded-lg cursor-pointer">
                <User className="w-5 h-5 text-gray-600" />
                <span className="text-gray-700 hidden sm:block">{userName}</span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 px-3 py-2 text-gray-700 hover:bg-gray-100 rounded-lg"
              >
                <LogOut className="w-5 h-5" />
                <span className="hidden sm:block">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="flex">
        {/* Sidebar */}
        <aside
          className={`
            fixed lg:sticky top-16 left-0 h-[calc(100vh-4rem)] w-64 bg-white border-r border-gray-200 
            transform transition-transform duration-200 ease-in-out z-40
            ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          `}
        >
          <div className="p-4 space-y-1 overflow-y-auto h-full">
            {sidebarItems.map((item, index) => (
              <Link
                key={index}
                to={item.path}
                className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-pink-50 hover:text-pink-600 rounded-lg transition-colors"
                onClick={() => setSidebarOpen(false)}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            ))}

            {/* Security Demo Section for Admin */}
            {role === 'admin' && (
              <>
                <div className="pt-4 mt-4 border-t border-gray-200">
                  <div className="flex items-center gap-2 px-4 py-2 text-gray-500 text-sm">
                    <Shield className="w-4 h-4" />
                    <span>Security Demo</span>
                  </div>
                </div>
                <Link
                  to="/security/encryption"
                  className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-pink-50 hover:text-pink-600 rounded-lg transition-colors"
                  onClick={() => setSidebarOpen(false)}
                >
                  <Shield className="w-5 h-5" />
                  <span>Encryption Status</span>
                </Link>
                <Link
                  to="/security/dlp-events"
                  className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-pink-50 hover:text-pink-600 rounded-lg transition-colors"
                  onClick={() => setSidebarOpen(false)}
                >
                  <Shield className="w-5 h-5" />
                  <span>DLP Events</span>
                </Link>
                <Link
                  to="/security/classification"
                  className="flex items-center gap-3 px-4 py-3 text-gray-700 hover:bg-pink-50 hover:text-pink-600 rounded-lg transition-colors"
                  onClick={() => setSidebarOpen(false)}
                >
                  <Shield className="w-5 h-5" />
                  <span>Classification Matrix</span>
                </Link>
              </>
            )}
          </div>
        </aside>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 z-30 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          ></div>
        )}

        {/* Main Content */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
