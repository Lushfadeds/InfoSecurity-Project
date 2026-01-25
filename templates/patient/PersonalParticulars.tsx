import { DashboardLayout } from '../layouts/DashboardLayout';
import { Home, Calendar, FileText, Pill, CreditCard, User, Eye, EyeOff, Shield, Edit2, Save, Lock, Upload } from 'lucide-react';
import { useState } from 'react';
import { maskData, maskPhone, maskEmail, maskAddress, maskPostalCode } from '../../utils/dataMaskingService';
import { toast } from '../ui/simple-toast';

const sidebarItems = [
  { icon: <Home className="w-5 h-5" />, label: 'Home', path: '/patient/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Book Appointment', path: '/patient/book-appointment' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Appointment History', path: '/patient/appointments' },
  { icon: <FileText className="w-5 h-5" />, label: 'Medical Certificates', path: '/patient/medical-certificates' },
  { icon: <Pill className="w-5 h-5" />, label: 'Prescriptions', path: '/patient/prescriptions' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Payment', path: '/patient/billing' },
  { icon: <User className="w-5 h-5" />, label: 'Personal Particulars', path: '/patient/profile' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/patient/upload' },
];

export function PersonalParticulars() {
  const [isEditing, setIsEditing] = useState(false);
  const [showUnmasked, setShowUnmasked] = useState({
    phone: false,
    email: false,
    address: false,
    emergencyPhone: false,
  });
  const [formData, setFormData] = useState({
    fullName: 'John Doe',
    nric: 'S1234567A', // Actual NRIC (will be masked in display)
    dateOfBirth: '1990-05-15',
    gender: 'Male',
    phone: '+65 9123 4567',
    email: 'john.doe@example.com',
    address: '123 Main Street #10-45',
    postalCode: '123456',
    emergencyContact: 'Jane Doe',
    emergencyPhone: '+65 9876 5432',
  });

  const toggleUnmasked = (field: keyof typeof showUnmasked) => {
    setShowUnmasked(prev => ({ ...prev, [field]: !prev[field] }));
  };

  // Patients see their own data with optional masking for security
  const displayNRIC = maskData(formData.nric, 'NRIC', 'patient');
  const displayPhone = (showUnmasked.phone || isEditing) ? formData.phone : maskPhone(formData.phone, 'patient');
  const displayEmail = (showUnmasked.email || isEditing) ? formData.email : maskEmail(formData.email, 'patient');
  const displayAddress = (showUnmasked.address || isEditing) ? formData.address : maskAddress(formData.address, 'patient');
  const displayEmergencyPhone = (showUnmasked.emergencyPhone || isEditing) ? formData.emergencyPhone : maskPhone(formData.emergencyPhone, 'patient');
  const displayPostalCode = (showUnmasked.address || isEditing) ? formData.postalCode : maskPostalCode(formData.postalCode, 'patient');

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSave = () => {
    setIsEditing(false);
    // Reset masking when saving
    setShowUnmasked({
      phone: false,
      email: false,
      address: false,
      emergencyPhone: false,
    });
    // Simulate saving changes
    toast.success('Personal particulars updated successfully', {
      description: 'Your information has been saved and encrypted.'
    });
  };

  const handleCancel = () => {
    setIsEditing(false);
    // Reset masking when canceling
    setShowUnmasked({
      phone: false,
      email: false,
      address: false,
      emergencyPhone: false,
    });
  };

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-4xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-gray-900">Personal Particulars</h1>
          {!isEditing ? (
            <button
              onClick={() => setIsEditing(true)}
              className="flex items-center gap-2 px-4 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
            >
              <Edit2 className="w-4 h-4" />
              Update Particulars
            </button>
          ) : (
            <div className="flex gap-2">
              <button
                onClick={handleCancel}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="flex items-center gap-2 px-4 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
              >
                <Save className="w-4 h-4" />
                Save Changes
              </button>
            </div>
          )}
        </div>

        {/* Security Notice */}
        <div className="mb-6 p-4 bg-pink-50 border border-pink-200 rounded-lg flex items-start gap-3">
          <Shield className="w-5 h-5 text-pink-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-pink-800">
            <p className="mb-1"><strong>Data Privacy Protection Active</strong></p>
            <p>Your personal information is encrypted and protected with field-level masking. When shared with staff or viewed in system logs, sensitive fields like NRIC, phone, email, and address are automatically masked or tokenized based on role-based access controls.</p>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Basic Information</h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-700 text-sm mb-2">Full Name</label>
              <input
                type="text"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">NRIC / FIN</label>
              <div className="relative">
                <input
                  type="text"
                  value={displayNRIC}
                  disabled
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-50"
                />
                <Lock className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              </div>
              <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
                <Shield className="w-3 h-3" />
                Classification-aware masking applied (Role: Patient)
              </p>
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Date of Birth</label>
              <input
                type="date"
                name="dateOfBirth"
                value={formData.dateOfBirth}
                onChange={handleChange}
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Gender</label>
              <select
                name="gender"
                value={formData.gender}
                onChange={handleChange}
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
              >
                <option>Male</option>
                <option>Female</option>
              </select>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Contact Information</h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-700 text-sm mb-2">Mobile Number</label>
              <div className="relative">
                <input
                  type="tel"
                  name="phone"
                  value={displayPhone}
                  onChange={handleChange}
                  disabled={!isEditing}
                  className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
                />
                {!isEditing && (
                  <button
                    onClick={() => toggleUnmasked('phone')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 hover:bg-gray-100 rounded"
                    title={showUnmasked.phone ? 'Hide Phone' : 'Reveal Phone'}
                  >
                    {showUnmasked.phone ? (
                      <EyeOff className="w-4 h-4 text-gray-600" />
                    ) : (
                      <Eye className="w-4 h-4 text-gray-600" />
                    )}
                  </button>
                )}
              </div>
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Email Address</label>
              <div className="relative">
                <input
                  type="email"
                  name="email"
                  value={displayEmail}
                  onChange={handleChange}
                  disabled={!isEditing}
                  className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
                />
                {!isEditing && (
                  <button
                    onClick={() => toggleUnmasked('email')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 hover:bg-gray-100 rounded"
                    title={showUnmasked.email ? 'Hide Email' : 'Reveal Email'}
                  >
                    {showUnmasked.email ? (
                      <EyeOff className="w-4 h-4 text-gray-600" />
                    ) : (
                      <Eye className="w-4 h-4 text-gray-600" />
                    )}
                  </button>
                )}
              </div>
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Address</label>
              <div className="relative">
                <input
                  type="text"
                  name="address"
                  value={displayAddress}
                  onChange={handleChange}
                  disabled={!isEditing}
                  className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
                />
                {!isEditing && (
                  <button
                    onClick={() => toggleUnmasked('address')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 hover:bg-gray-100 rounded"
                    title={showUnmasked.address ? 'Hide Address' : 'Reveal Address'}
                  >
                    {showUnmasked.address ? (
                      <EyeOff className="w-4 h-4 text-gray-600" />
                    ) : (
                      <Eye className="w-4 h-4 text-gray-600" />
                    )}
                  </button>
                )}
              </div>
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Postal Code</label>
              <input
                type="text"
                name="postalCode"
                value={displayPostalCode}
                onChange={handleChange}
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
              />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Emergency Contact</h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-700 text-sm mb-2">Contact Name</label>
              <input
                type="text"
                name="emergencyContact"
                value={formData.emergencyContact}
                onChange={handleChange}
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Contact Number</label>
              <div className="relative">
                <input
                  type="tel"
                  name="emergencyPhone"
                  value={displayEmergencyPhone}
                  onChange={handleChange}
                  disabled={!isEditing}
                  className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 disabled:bg-gray-50"
                />
                {!isEditing && (
                  <button
                    onClick={() => toggleUnmasked('emergencyPhone')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 hover:bg-gray-100 rounded"
                    title={showUnmasked.emergencyPhone ? 'Hide Phone' : 'Reveal Phone'}
                  >
                    {showUnmasked.emergencyPhone ? (
                      <EyeOff className="w-4 h-4 text-gray-600" />
                    ) : (
                      <Eye className="w-4 h-4 text-gray-600" />
                    )}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {isEditing && (
          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-blue-800">
              <p className="mb-1">Changes to your personal particulars will require MFA verification.</p>
              <p>You will receive a verification code via SMS to confirm these changes.</p>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}