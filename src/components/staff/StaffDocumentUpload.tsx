import { useState } from 'react';
import { Upload, FileText, X, CheckCircle, Calendar, DollarSign, Users } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Users className="w-5 h-5" />, label: 'Dashboard', path: '/staff/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Create Appointment', path: '/staff/create-appointment' },
  { icon: <DollarSign className="w-5 h-5" />, label: 'Billing', path: '/staff/billing' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/staff/upload' },
];

interface UploadedFile {
  id: string;
  name: string;
  type: string;
  size: string;
  patient: string;
  status: 'uploading' | 'completed' | 'failed';
}

export function StaffDocumentUpload() {
  const [selectedPatient, setSelectedPatient] = useState('');
  const [documentType, setDocumentType] = useState('');
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([
    {
      id: '1',
      name: 'lab-results-2024.pdf',
      type: 'Lab Results',
      size: '1.2 MB',
      patient: 'John Doe',
      status: 'completed'
    }
  ]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const newFiles = Array.from(files).map((file, index) => ({
        id: Date.now().toString() + index,
        name: file.name,
        type: documentType,
        size: (file.size / 1024 / 1024).toFixed(2) + ' MB',
        patient: selectedPatient,
        status: 'uploading' as const
      }));
      
      setUploadedFiles([...uploadedFiles, ...newFiles]);
      
      // Simulate upload completion
      setTimeout(() => {
        setUploadedFiles(prev => prev.map(f => 
          newFiles.find(nf => nf.id === f.id) ? { ...f, status: 'completed' } : f
        ));
      }, 2000);
    }
  };

  const removeFile = (id: string) => {
    setUploadedFiles(uploadedFiles.filter(f => f.id !== id));
  };

  return (
    <DashboardLayout role="staff" sidebarItems={sidebarItems} userName="Alice Wong">
      <div className="max-w-6xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Document Upload</h1>
          <p className="text-gray-600">Upload patient documents and medical records</p>
        </div>

        {/* Upload Form */}
        <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
          <div className="grid md:grid-cols-2 gap-4 mb-6">
            <div>
              <label className="block text-gray-700 mb-2">
                Patient Name/NRIC
              </label>
              <input
                type="text"
                value={selectedPatient}
                onChange={(e) => setSelectedPatient(e.target.value)}
                placeholder="Search patient..."
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
            </div>

            <div>
              <label className="block text-gray-700 mb-2">
                Document Type
              </label>
              <select
                value={documentType}
                onChange={(e) => setDocumentType(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              >
                <option value="">Select type...</option>
                <option value="Lab Results">Lab Results</option>
                <option value="X-Ray">X-Ray</option>
                <option value="MRI Scan">MRI Scan</option>
                <option value="Medical Certificate">Medical Certificate</option>
                <option value="Referral Letter">Referral Letter</option>
                <option value="Insurance">Insurance Documents</option>
                <option value="Other">Other</option>
              </select>
            </div>
          </div>

          {/* Upload Area */}
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
            <Upload className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-600 mb-2">
              Drag and drop files here, or click to browse
            </p>
            <p className="text-sm text-gray-500 mb-4">
              Supports PDF, JPG, PNG up to 10MB
            </p>
            <label className="inline-block">
              <input
                type="file"
                multiple
                accept=".pdf,.jpg,.jpeg,.png"
                onChange={handleFileUpload}
                className="hidden"
                disabled={!selectedPatient || !documentType}
              />
              <span className={`px-6 py-2 rounded-lg cursor-pointer ${
                selectedPatient && documentType
                  ? 'bg-pink-600 text-white hover:bg-pink-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}>
                Choose Files
              </span>
            </label>
          </div>
        </div>

        {/* Uploaded Files List */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Uploaded Documents</h2>
          </div>
          <div className="divide-y divide-gray-200">
            {uploadedFiles.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                No documents uploaded yet
              </div>
            ) : (
              uploadedFiles.map((file) => (
                <div key={file.id} className="p-4 flex items-center justify-between hover:bg-gray-50">
                  <div className="flex items-center gap-3 flex-1">
                    <FileText className="w-10 h-10 text-pink-600" />
                    <div>
                      <p className="text-gray-900">{file.name}</p>
                      <p className="text-sm text-gray-500">
                        {file.type} • {file.size} • {file.patient}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    {file.status === 'uploading' && (
                      <span className="text-sm text-blue-600">Uploading...</span>
                    )}
                    {file.status === 'completed' && (
                      <CheckCircle className="w-5 h-5 text-green-600" />
                    )}
                    <button
                      onClick={() => removeFile(file.id)}
                      className="p-1 hover:bg-gray-200 rounded"
                    >
                      <X className="w-5 h-5 text-gray-500" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}