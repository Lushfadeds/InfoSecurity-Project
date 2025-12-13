import { useState } from 'react';
import { Search, Package, CheckCircle, AlertCircle } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

interface Medication {
  name: string;
  dosage: string;
  quantity: string;
  instructions: string;
  inStock: boolean;
}

interface Prescription {
  id: string;
  patient: string;
  nric: string;
  doctor: string;
  date: string;
  medications: Medication[];
  status: 'pending' | 'dispensed';
}

export function DispenseMedication() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedPrescription, setSelectedPrescription] = useState<Prescription | null>(null);

  const prescriptions: Prescription[] = [
    {
      id: 'RX001',
      patient: 'Sarah Lee',
      nric: 'S9234567A',
      doctor: 'Dr. Chen Wei Ming',
      date: '2024-12-12',
      status: 'pending',
      medications: [
        { name: 'Paracetamol', dosage: '500mg', quantity: '20 tablets', instructions: 'Take 1-2 tablets every 6 hours as needed', inStock: true },
        { name: 'Amoxicillin', dosage: '250mg', quantity: '21 capsules', instructions: 'Take 1 capsule 3 times daily for 7 days', inStock: true },
        { name: 'Cetirizine', dosage: '10mg', quantity: '14 tablets', instructions: 'Take 1 tablet once daily at bedtime', inStock: true }
      ]
    },
    {
      id: 'RX002',
      patient: 'James Tan',
      nric: 'S8756432B',
      doctor: 'Dr. Lim Hui Ling',
      date: '2024-12-12',
      status: 'pending',
      medications: [
        { name: 'Omeprazole', dosage: '20mg', quantity: '28 capsules', instructions: 'Take 1 capsule daily before breakfast', inStock: true },
        { name: 'Metformin', dosage: '500mg', quantity: '60 tablets', instructions: 'Take 1 tablet twice daily with meals', inStock: false }
      ]
    }
  ];

  const filteredPrescriptions = prescriptions.filter(p =>
    p.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    p.patient.toLowerCase().includes(searchTerm.toLowerCase()) ||
    p.nric.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDispense = () => {
    if (selectedPrescription) {
      alert(`Prescription ${selectedPrescription.id} dispensed successfully`);
      setSelectedPrescription(null);
    }
  };

  return (
    <DashboardLayout role="pharmacy">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Dispense Medication</h1>
          <p className="text-gray-600">Process and dispense patient prescriptions</p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Prescriptions List */}
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="border-b border-gray-200 p-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                <input
                  type="text"
                  placeholder="Search by RX ID, patient name, or NRIC..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                />
              </div>
            </div>
            
            <div className="divide-y divide-gray-200 max-h-[600px] overflow-y-auto">
              {filteredPrescriptions.map((prescription) => (
                <div
                  key={prescription.id}
                  onClick={() => setSelectedPrescription(prescription)}
                  className={`p-4 cursor-pointer hover:bg-gray-50 ${
                    selectedPrescription?.id === prescription.id ? 'bg-pink-50 border-l-4 border-pink-600' : ''
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-gray-900">{prescription.patient}</p>
                      <p className="text-sm text-gray-500">
                        {prescription.id} • NRIC: ****{prescription.nric.slice(-4)}
                      </p>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      prescription.status === 'pending'
                        ? 'bg-orange-100 text-orange-700'
                        : 'bg-green-100 text-green-700'
                    }`}>
                      {prescription.status}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600">Dr. {prescription.doctor}</p>
                  <p className="text-sm text-gray-500 mt-1">
                    {prescription.medications.length} medication(s) • {prescription.date}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Prescription Details */}
          <div>
            {selectedPrescription ? (
              <div className="bg-white rounded-lg border border-gray-200">
                <div className="border-b border-gray-200 p-4">
                  <h2 className="text-pink-900">Prescription Details</h2>
                </div>
                
                <div className="p-4 space-y-4">
                  {/* Patient Info */}
                  <div className="grid grid-cols-2 gap-4 pb-4 border-b border-gray-200">
                    <div>
                      <p className="text-sm text-gray-500 mb-1">Patient</p>
                      <p className="text-gray-900">{selectedPrescription.patient}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500 mb-1">NRIC</p>
                      <p className="text-gray-900">****{selectedPrescription.nric.slice(-4)}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500 mb-1">Prescriber</p>
                      <p className="text-gray-900">{selectedPrescription.doctor}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-500 mb-1">Date</p>
                      <p className="text-gray-900">{selectedPrescription.date}</p>
                    </div>
                  </div>

                  {/* Medications */}
                  <div>
                    <h3 className="text-gray-900 mb-3">Medications</h3>
                    <div className="space-y-3">
                      {selectedPrescription.medications.map((med, index) => (
                        <div key={index} className={`p-3 rounded-lg border ${
                          med.inStock ? 'border-gray-200 bg-gray-50' : 'border-red-200 bg-red-50'
                        }`}>
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Package className={`w-5 h-5 ${med.inStock ? 'text-gray-600' : 'text-red-600'}`} />
                              <div>
                                <p className="text-gray-900">{med.name} {med.dosage}</p>
                                <p className="text-sm text-gray-600">{med.quantity}</p>
                              </div>
                            </div>
                            {med.inStock ? (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            ) : (
                              <AlertCircle className="w-5 h-5 text-red-600" />
                            )}
                          </div>
                          <p className="text-sm text-gray-600 ml-7">{med.instructions}</p>
                          {!med.inStock && (
                            <p className="text-sm text-red-700 ml-7 mt-1">Out of stock</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3 pt-4">
                    <button
                      onClick={handleDispense}
                      disabled={selectedPrescription.medications.some(m => !m.inStock)}
                      className="flex-1 px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
                    >
                      Dispense Medication
                    </button>
                    <button
                      onClick={() => setSelectedPrescription(null)}
                      className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
                <Package className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-500">
                  Select a prescription from the list to view details
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}