import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, AlertTriangle, CheckCircle, File } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Calendar className="w-5 h-5" />, label: 'Dashboard', path: '/patient/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Book Appointment', path: '/patient/book-appointment' },
  { icon: <Clock className="w-5 h-5" />, label: 'Appointment History', path: '/patient/appointments' },
  { icon: <FileText className="w-5 h-5" />, label: 'Medical Certificates', path: '/patient/medical-certificates' },
  { icon: <Pill className="w-5 h-5" />, label: 'Prescriptions', path: '/patient/prescriptions' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Payment', path: '/patient/billing' },
  { icon: <User className="w-5 h-5" />, label: 'Personal Particulars', path: '/patient/profile' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/patient/upload' },
];

const uploadedDocuments = [
  {
    id: '1',
    name: 'Lab-Results-Blood-Test.pdf',
    uploadDate: '2024-12-05',
    classification: 'Confidential',
    dlpStatus: 'Passed',
    size: '245 KB',
  },
  {
    id: '2',
    name: 'Referral-Letter-Specialist.pdf',
    uploadDate: '2024-11-20',
    classification: 'Confidential',
    dlpStatus: 'Passed',
    size: '189 KB',
  },
];

export function UploadDocuments() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [classification, setClassification] = useState('Confidential');

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setSelectedFiles(Array.from(e.target.files));
    }
  };

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Upload Documents</h1>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-blue-800">
              <p className="mb-1"><strong>DLP Protection Enabled</strong></p>
              <p>All uploaded documents are automatically scanned for sensitive data. Documents containing 
              NRIC, medical records, or other PHI will be encrypted and classified accordingly.</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Upload New Document</h2>

          <div className="border-2 border-dashed border-gray-300 rounded-xl p-8 text-center hover:border-pink-400 transition-colors cursor-pointer">
            <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-700 mb-2">Click to upload or drag and drop</p>
            <p className="text-sm text-gray-500 mb-4">PDF, JPG, PNG (Max 10MB)</p>
            <input
              type="file"
              multiple
              accept=".pdf,.jpg,.jpeg,.png"
              onChange={handleFileSelect}
              className="hidden"
              id="file-upload"
            />
            <label
              htmlFor="file-upload"
              className="inline-block px-6 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 cursor-pointer"
            >
              Select Files
            </label>
          </div>

          {selectedFiles.length > 0 && (
            <div className="mt-4 space-y-2">
              {selectedFiles.map((file, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <File className="w-5 h-5 text-pink-600" />
                    <div>
                      <p className="text-sm text-gray-900">{file.name}</p>
                      <p className="text-xs text-gray-600">{(file.size / 1024).toFixed(2)} KB</p>
                    </div>
                  </div>
                  <span className="text-xs text-gray-500">Pending</span>
                </div>
              ))}
            </div>
          )}

          {selectedFiles.length > 0 && (
            <div className="mt-4">
              <label className="block text-gray-700 text-sm mb-2">Document Classification</label>
              <select
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              >
                <option value="Internal">Internal</option>
                <option value="Confidential">Confidential</option>
                <option value="Restricted">Restricted</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">
                Classification may be adjusted after DLP scan
              </p>
            </div>
          )}

          {selectedFiles.length > 0 && (
            <button className="mt-4 w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600">
              Upload Documents
            </button>
          )}
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Uploaded Documents</h2>

          <div className="space-y-3">
            {uploadedDocuments.map((doc) => (
              <div key={doc.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center">
                    <FileText className="w-6 h-6 text-pink-600" />
                  </div>
                  <div>
                    <p className="text-gray-900 text-sm">{doc.name}</p>
                    <p className="text-gray-600 text-xs">
                      Uploaded: {new Date(doc.uploadDate).toLocaleDateString('en-SG')} • {doc.size}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="px-2 py-0.5 bg-orange-100 text-orange-800 text-xs rounded">
                        {doc.classification}
                      </span>
                      <span className="flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-800 text-xs rounded">
                        <CheckCircle className="w-3 h-3" />
                        DLP {doc.dlpStatus}
                      </span>
                    </div>
                  </div>
                </div>
                <button className="text-pink-600 hover:text-pink-700 text-sm">
                  Download
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
