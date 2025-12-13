import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

// Public Pages
import { HomePage } from './components/public/HomePage';
import { AboutPage } from './components/public/AboutPage';
import { ContactPage } from './components/public/ContactPage';
import { FAQPage } from './components/public/FAQPage';
import { AnnouncementsPage } from './components/public/AnnouncementsPage';

// Auth Pages
import { LoginPage } from './components/auth/LoginPage';
import { SignupPage } from './components/auth/SignupPage';
import { ResetPasswordPage } from './components/auth/ResetPasswordPage';

// Patient Portal
import { PatientDashboard } from './components/patient/PatientDashboard';
import { BookAppointment } from './components/patient/BookAppointment';
import { AppointmentHistory } from './components/patient/AppointmentHistory';
import { MedicalCertificates } from './components/patient/MedicalCertificates';
import { Prescriptions } from './components/patient/Prescriptions';
import { BillingPayment } from './components/patient/BillingPayment';
import { PersonalParticulars } from './components/patient/PersonalParticulars';
import { UploadDocuments } from './components/patient/UploadDocuments';
import { MakePayment } from './components/patient/MakePayment';
import { RequestRefill } from './components/patient/RequestRefill';

// Doctor Portal
import { DoctorDashboard } from './components/doctor/DoctorDashboard';
import { PatientLookup } from './components/doctor/PatientLookup';
import { ConsultationPage } from './components/doctor/ConsultationPage';
import { WriteMC } from './components/doctor/WriteMC';
import { WritePrescription } from './components/doctor/WritePrescription';
import { DoctorProfile } from './components/doctor/DoctorProfile';

// Staff Portal
import { StaffDashboard } from './components/staff/StaffDashboard';
import { CreateAppointment } from './components/staff/CreateAppointment';
import { StaffBilling } from './components/staff/StaffBilling';
import { StaffDocumentUpload } from './components/staff/StaffDocumentUpload';

// Pharmacy Portal
import { PharmacyDashboard } from './components/pharmacy/PharmacyDashboard';
import { DispenseMedication } from './components/pharmacy/DispenseMedication';
import { InventoryManagement } from './components/pharmacy/InventoryManagement';

// Admin Portal
import { AdminDashboard } from './components/admin/AdminDashboard';
import { UserManagement } from './components/admin/UserManagement';
import { AuditLogs } from './components/admin/AuditLogs';
import { BackupRecovery } from './components/admin/BackupRecovery';
import { DataRetention } from './components/admin/DataRetention';

// Security Demo Pages
import { EncryptionStatus } from './components/security/EncryptionStatus';
import { DLPEvents } from './components/security/DLPEvents';
import { ClassificationMatrix } from './components/security/ClassificationMatrix';

export default function App() {
  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<HomePage />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="/contact" element={<ContactPage />} />
        <Route path="/faq" element={<FAQPage />} />
        <Route path="/announcements" element={<AnnouncementsPage />} />

        {/* Auth Routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />

        {/* Patient Portal Routes */}
        <Route path="/patient/dashboard" element={<PatientDashboard />} />
        <Route path="/patient/book-appointment" element={<BookAppointment />} />
        <Route path="/patient/appointments" element={<AppointmentHistory />} />
        <Route path="/patient/medical-certificates" element={<MedicalCertificates />} />
        <Route path="/patient/prescriptions" element={<Prescriptions />} />
        <Route path="/patient/billing" element={<BillingPayment />} />
        <Route path="/patient/profile" element={<PersonalParticulars />} />
        <Route path="/patient/upload" element={<UploadDocuments />} />
        <Route path="/patient/make-payment" element={<MakePayment />} />
        <Route path="/patient/request-refill" element={<RequestRefill />} />

        {/* Doctor Portal Routes */}
        <Route path="/doctor/dashboard" element={<DoctorDashboard />} />
        <Route path="/doctor/patient-lookup" element={<PatientLookup />} />
        <Route path="/doctor/consultation/:patientId?" element={<ConsultationPage />} />
        <Route path="/doctor/write-mc" element={<WriteMC />} />
        <Route path="/doctor/write-prescription" element={<WritePrescription />} />
        <Route path="/doctor/profile" element={<DoctorProfile />} />

        {/* Staff Portal Routes */}
        <Route path="/staff/dashboard" element={<StaffDashboard />} />
        <Route path="/staff/create-appointment" element={<CreateAppointment />} />
        <Route path="/staff/billing" element={<StaffBilling />} />
        <Route path="/staff/upload" element={<StaffDocumentUpload />} />

        {/* Pharmacy Portal Routes */}
        <Route path="/pharmacy/dashboard" element={<PharmacyDashboard />} />
        <Route path="/pharmacy/dispense" element={<DispenseMedication />} />
        <Route path="/pharmacy/inventory" element={<InventoryManagement />} />

        {/* Admin Portal Routes */}
        <Route path="/admin/dashboard" element={<AdminDashboard />} />
        <Route path="/admin/users" element={<UserManagement />} />
        <Route path="/admin/audit-logs" element={<AuditLogs />} />
        <Route path="/admin/backup" element={<BackupRecovery />} />
        <Route path="/admin/data-retention" element={<DataRetention />} />

        {/* Security Demo Routes */}
        <Route path="/security/encryption" element={<EncryptionStatus />} />
        <Route path="/security/dlp-events" element={<DLPEvents />} />
        <Route path="/security/classification" element={<ClassificationMatrix />} />
      </Routes>
    </Router>
  );
}