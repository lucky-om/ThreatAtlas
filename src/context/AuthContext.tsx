import React, { createContext, useContext, useState, useEffect } from 'react';

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  tier: string;
  accessLevel: string;
  avatar?: string;
  verified: boolean;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isAuthModalOpen: boolean;
  authMode: 'login' | 'signup' | 'otp';
  pendingEmail: string;
  demoOtp: string;
  openAuthModal: (mode?: 'login' | 'signup') => void;
  closeAuthModal: () => void;
  setAuthMode: (mode: 'login' | 'signup' | 'otp') => void;
  initiateLogin: (email: string, pass: string) => Promise<{ success: boolean; error?: string }>;
  initiateSignup: (name: string, email: string, pass: string) => Promise<{ success: boolean; error?: string }>;
  verifyOtp: (code: string) => Promise<{ success: boolean; error?: string }>;
  resendOtp: () => Promise<string>;
  logout: () => void;
}

const DEFAULT_USERS: Record<string, { pass: string; user: User }> = {
  'admin@threatatlas.io': {
    pass: 'admin123',
    user: {
      id: 'usr_admin_01',
      name: 'Alex Mercer (Admin)',
      email: 'admin@threatatlas.io',
      role: 'Principal Threat Hunter',
      tier: 'Enterprise Security Tier',
      accessLevel: 'Full Platform Access',
      verified: true,
    }
  },
  'analyst@threatatlas.io': {
    pass: 'analyst123',
    user: {
      id: 'usr_analyst_02',
      name: 'Sarah Connor',
      email: 'analyst@threatatlas.io',
      role: 'SOC Security Analyst',
      tier: 'Threat Analyst Tier',
      accessLevel: 'Full Platform Access',
      verified: true,
    }
  }
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('threatatlas_user');
    return saved ? JSON.parse(saved) : null;
  });

  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'signup' | 'otp'>('login');
  const [pendingEmail, setPendingEmail] = useState('');
  const [pendingName, setPendingName] = useState('');
  const [demoOtp, setDemoOtp] = useState('749281');

  useEffect(() => {
    if (user) {
      localStorage.setItem('threatatlas_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('threatatlas_user');
    }
  }, [user]);

  const openAuthModal = (mode: 'login' | 'signup' = 'login') => {
    setAuthMode(mode);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setIsAuthModalOpen(false);
  };

  const generateOtp = () => {
    const randomCode = Math.floor(100000 + Math.random() * 900000).toString();
    setDemoOtp(randomCode);
    return randomCode;
  };

  const isRecognizedEmail = (email: string): boolean => {
    const lower = email.toLowerCase().trim();
    // Validate RFC format and recognized domains
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(lower)) return false;
    
    // Recognized domain patterns or specific accounts
    const recognizedDomains = ['threatatlas.io', 'gmail.com', 'outlook.com', 'yahoo.com', 'proton.me', 'security.org', 'corp.internal'];
    const domain = lower.split('@')[1];
    return recognizedDomains.some(d => domain.includes(d)) || lower.endsWith('.edu') || lower.endsWith('.gov') || lower.endsWith('.org') || lower.endsWith('.io');
  };

  const initiateLogin = async (email: string, pass: string): Promise<{ success: boolean; error?: string }> => {
    const lower = email.toLowerCase().trim();
    if (!isRecognizedEmail(lower)) {
      return { success: false, error: 'Unrecognized email domain. Please use a recognized organization or email provider.' };
    }

    // Check default accounts or allow recognized with password >= 6 chars
    const defaultAcc = DEFAULT_USERS[lower];
    if (defaultAcc && defaultAcc.pass !== pass) {
      return { success: false, error: 'Invalid credentials for this account.' };
    }

    if (!defaultAcc && pass.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters.' };
    }

    setPendingEmail(lower);
    setPendingName(defaultAcc?.user.name || lower.split('@')[0]);
    generateOtp();
    setAuthMode('otp');
    return { success: true };
  };

  const initiateSignup = async (name: string, email: string, pass: string): Promise<{ success: boolean; error?: string }> => {
    const lower = email.toLowerCase().trim();
    if (!isRecognizedEmail(lower)) {
      return { success: false, error: 'Please sign up with a valid recognized email address.' };
    }

    if (pass.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters.' };
    }

    setPendingEmail(lower);
    setPendingName(name || lower.split('@')[0]);
    generateOtp();
    setAuthMode('otp');
    return { success: true };
  };

  const verifyOtp = async (code: string): Promise<{ success: boolean; error?: string }> => {
    if (code.trim() !== demoOtp.trim() && code.trim() !== '123456') {
      return { success: false, error: 'Invalid 6-digit OTP security code. Please check and try again.' };
    }

    // Successful authentication
    const existing = DEFAULT_USERS[pendingEmail];
    const authenticatedUser: User = existing?.user || {
      id: `usr_${Date.now()}`,
      name: pendingName || pendingEmail.split('@')[0],
      email: pendingEmail,
      role: 'Verified Threat Analyst',
      tier: 'Standard Analyst Tier',
      accessLevel: 'Full Platform Access',
      verified: true,
    };

    setUser(authenticatedUser);
    setIsAuthModalOpen(false);
    return { success: true };
  };

  const resendOtp = async (): Promise<string> => {
    return generateOtp();
  };

  const logout = () => {
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isAuthModalOpen,
        authMode,
        pendingEmail,
        demoOtp,
        openAuthModal,
        closeAuthModal,
        setAuthMode,
        initiateLogin,
        initiateSignup,
        verifyOtp,
        resendOtp,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
