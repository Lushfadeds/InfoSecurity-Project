# PinkHealth - HTML/CSS (Tailwind) Conversion

This is a complete conversion of the React/TypeScript healthcare portal application to vanilla HTML, CSS (Tailwind), and JavaScript.

## 📋 File Structure

```
├── index.html                 # Home page
├── login.html                 # Login page (multi-role support)
├── signup.html                # User registration (3-step process)
├── reset-password.html        # Password reset
├── patient-dashboard.html     # Patient portal dashboard
├── doctor-dashboard.html      # Doctor portal dashboard
├── staff-dashboard.html       # Staff portal dashboard
├── admin-dashboard.html       # Admin portal dashboard
├── pharmacy-dashboard.html    # Pharmacy portal dashboard
├── about.html                 # About PinkHealth page
├── contact.html               # Contact form page
├── faq.html                   # Frequently Asked Questions
└── announcements.html         # News & Announcements
```

## ✨ Features Implemented

### Public Pages
- **Home Page** - Hero section with feature highlights and portal access cards
- **About Page** - Mission, vision, core values, and leadership team
- **Contact Page** - Contact form and multiple contact methods
- **FAQ Page** - Accordion-style FAQ with common questions
- **Announcements** - News and updates feed

### Authentication
- **Login Page** - Multi-role selection (Patient, Doctor, Staff, Admin)
  - Two-step authentication (credentials + MFA)
  - Role-based portal selection
  - Remember me functionality
  
- **Signup Page** - Multi-step registration
  - Step 1: Personal information (name, NRIC, phone)
  - Step 2: Account creation (email, password)
  - Step 3: Verification and terms acceptance
  - Progress indicator

- **Password Reset** - Email-based password recovery

### Dashboards

#### Patient Dashboard
- Welcome section with masked NRIC
- Pending actions alerts
- Quick action cards (Book Appointment, Medical Certificates, Prescriptions, Billing)
- Upcoming appointments list
- Recent documents section
- Navigation sidebar with menu items

#### Doctor Dashboard
- Greeting based on role
- Pending tasks (sign MC, review lab results)
- Quick action cards (Patient Lookup, Consultation, Write MC, Write Prescription)
- Today's appointments with patient details
- Color-coded appointment status

#### Staff Dashboard
- Key metrics (Total Patients, Appointments, Pending Tasks, Revenue)
- Quick action buttons
- Recent activity log
- Sidebar navigation

#### Admin Dashboard
- System health metrics
- Active user count
- Data backup status
- Security events counter
- System status indicators for all services
- Admin action cards

#### Pharmacy Dashboard
- Daily statistics
- Pending prescriptions queue
- Low stock alerts
- Medication dispensing interface
- Inventory management

## 🎨 Styling

- **Tailwind CSS** - All styling uses Tailwind utility classes
- **CDN-based** - Loads Tailwind from CDN (`https://cdn.tailwindcss.com`)
- **Responsive Design** - Mobile-first, adapts to all screen sizes
- **Color Scheme** - Pink primary (#ec4899) with role-specific accent colors:
  - Patient: Pink
  - Doctor: Blue
  - Staff: Purple
  - Admin: Red
  - Pharmacy: Green

## 🔐 Security & Data

- Mock authentication system using localStorage
- Session management (check if user is logged in on dashboard pages)
- Client-side form validation
- MFA simulation in login flow

## 📱 User Interactions

### Login Flow
1. Select user role
2. Enter credentials
3. Receive and enter MFA code
4. Redirected to role-specific dashboard

### Signup Flow
1. Enter personal information
2. Create account credentials
3. Verify with code
4. Accept terms and create account
5. Redirected to login

### Dashboard Navigation
- Each dashboard has a sidebar with role-specific menu items
- Navigation links throughout the site
- Logout button in top navigation

## 🚀 Getting Started

1. **Open in Browser** - Simply open any `.html` file in a web browser
2. **No Build Process** - Works as-is, no compilation needed
3. **No Backend Required** - All functionality is client-side (for demo purposes)

### Demo Flow
1. Start at `index.html`
2. Click "Login to Portal"
3. Try different roles (Patient, Doctor, Staff, Admin)
4. Use any email/password and 6-digit code
5. Explore the role-specific dashboards

## 📊 Key Conversions from React

### Component Structure
- **React Components** → **HTML Pages** (one-to-one mapping)
- **React State** → **localStorage** (client-side data persistence)
- **React Routing** → **HTML links and anchor tags**
- **React Props** → **URL parameters and data attributes**

### Examples

**React Hook State:**
```typescript
const [selectedRole, setSelectedRole] = useState('patient');
```

**HTML/JS Equivalent:**
```javascript
let selectedRole = localStorage.getItem('selectedRole') || 'patient';
// Or
let selectedRole = 'patient';
localStorage.setItem('selectedRole', selectedRole);
```

**React Conditional Rendering:**
```typescript
{showMFA ? <MFAForm /> : <LoginForm />}
```

**HTML/JS Equivalent:**
```html
<div id="step1" class="space-y-4"><!-- credentials form --></div>
<div id="step2" class="space-y-4 hidden"><!-- MFA form --></div>
```

### Icon Changes
- **Lucide React Icons** → **Inline SVG icons**
- All icons are self-contained SVG elements in the HTML

### Styling
- **Tailwind CSS Classes** - Preserved from original React components
- **No CSS files** - All styling through CDN-loaded Tailwind

## 🔧 Customization

### Adding New Pages
1. Create new `.html` file
2. Copy navigation bar from existing page
3. Use same Tailwind classes and structure
4. Link from navigation menus

### Modifying Styles
- Edit Tailwind classes directly in HTML
- All classes are inline (no separate CSS files needed)
- Colors and spacing use Tailwind's standardized scale

### Adding Functionality
- Add JavaScript event listeners in `<script>` tags
- Use localStorage for persistence
- No dependencies required

## 📝 Notes

- This is a **client-side only** implementation suitable for prototyping and demos
- For production, implement proper backend authentication and data management
- localStorage is cleared when browser cache is cleared
- Mobile responsiveness tested on common device sizes
- Forms have basic HTML5 validation

## 🎯 Page Routes

| Route | File | Purpose |
|-------|------|---------|
| `/` | `index.html` | Home page |
| `/login` | `login.html` | Authentication |
| `/signup` | `signup.html` | User registration |
| `/reset-password` | `reset-password.html` | Password recovery |
| `/patient/dashboard` | `patient-dashboard.html` | Patient portal |
| `/doctor/dashboard` | `doctor-dashboard.html` | Doctor portal |
| `/staff/dashboard` | `staff-dashboard.html` | Staff portal |
| `/admin/dashboard` | `admin-dashboard.html` | Admin portal |
| `/pharmacy/dashboard` | `pharmacy-dashboard.html` | Pharmacy portal |
| `/about` | `about.html` | About page |
| `/contact` | `contact.html` | Contact page |
| `/faq` | `faq.html` | FAQs |
| `/announcements` | `announcements.html` | News |

## ✅ Completed Features

- [x] Home page with hero and feature sections
- [x] Multi-role login system
- [x] Three-step signup process
- [x] All 5 portal dashboards (Patient, Doctor, Staff, Admin, Pharmacy)
- [x] Public information pages (About, Contact, FAQ, Announcements)
- [x] Responsive design for mobile and desktop
- [x] Navigation and sidebar menus
- [x] Session management (logout functionality)
- [x] Accordion components (FAQ)
- [x] Form validation
- [x] Role-based color schemes

## 🌐 Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

No special polyfills needed - uses standard HTML5 and CSS3 features.

---

**Note:** This conversion maintains the design and user experience of the original React application while simplifying it to vanilla HTML/CSS/JS for easier distribution and modification.
