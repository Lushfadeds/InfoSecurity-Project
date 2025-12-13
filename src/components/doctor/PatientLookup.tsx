import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Shield } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

const searchResults = [
  { id: '1', name: 'John Doe', nric: 'S****123A', dob: '1990-05-15', lastVisit: '2024-12-10' },
  { id: '2', name: 'Jane Smith', nric: 'S****456B', dob: '1985-08-22', lastVisit: '2024-11-28' },
];

export function PatientLookup() {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchBy, setSearchBy] = useState('name');

  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Patient Lookup</h1>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 flex items-start gap-3">
          <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-blue-800">
            <p>Patient data access is logged for audit purposes. NRIC numbers are masked based on DLP policies.</p>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <div className="flex gap-3 mb-4">
            <select
              value={searchBy}
              onChange={(e) => setSearchBy(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="name">Name</option>
              <option value="nric">NRIC</option>
              <option value="phone">Phone</option>
            </select>
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={`Search by ${searchBy}...`}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <button className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
              Search
            </button>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-gray-700">Patient Name</th>
                <th className="px-6 py-3 text-left text-gray-700">NRIC</th>
                <th className="px-6 py-3 text-left text-gray-700">Date of Birth</th>
                <th className="px-6 py-3 text-left text-gray-700">Last Visit</th>
                <th className="px-6 py-3 text-left text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {searchResults.map((patient) => (
                <tr key={patient.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-gray-900">{patient.name}</td>
                  <td className="px-6 py-4 text-gray-600">{patient.nric}</td>
                  <td className="px-6 py-4 text-gray-600">{new Date(patient.dob).toLocaleDateString('en-SG')}</td>
                  <td className="px-6 py-4 text-gray-600">{new Date(patient.lastVisit).toLocaleDateString('en-SG')}</td>
                  <td className="px-6 py-4">
                    <a href={`/doctor/consultation/${patient.id}`} className="text-blue-600 hover:text-blue-700">
                      View Record
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
