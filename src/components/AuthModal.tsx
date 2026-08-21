import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

export const AuthModal: React.FC = () => {
  const {
    isAuthModalOpen,
    closeAuthModal,
    authMode,
    setAuthMode,
    initiateLogin,
    initiateSignup,
    verifyOtp,
    resendOtp,
    pendingEmail,
    demoOtp,
  } = useAuth();

  // Login form state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // OTP form state
  const [otpDigits, setOtpDigits] = useState(['', '', '', '', '', '']);
  const [countdown, setCountdown] = useState(60);
  const [otpResent, setOtpResent] = useState(false);

  const otpInputsRef = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    setError(null);
    if (authMode === 'otp') {
      setCountdown(60);
      setOtpDigits(['', '', '', '', '', '']);
      setTimeout(() => otpInputsRef.current[0]?.focus(), 100);
    }
  }, [authMode, isAuthModalOpen]);

  useEffect(() => {
    let timer: any;
    if (authMode === 'otp' && countdown > 0) {
      timer = setInterval(() => setCountdown(c => c - 1), 1000);
    }
    return () => clearInterval(timer);
  }, [authMode, countdown]);

  if (!isAuthModalOpen) return null;

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const res = await initiateLogin(email, password);
    setLoading(false);
    if (!res.success) {
      setError(res.error || 'Authentication failed');
    }
  };

  const handleSignupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const res = await initiateSignup(name, email, password);
    setLoading(false);
    if (!res.success) {
      setError(res.error || 'Registration failed');
    }
  };

  const handleQuickDemo = (demoType: 'admin' | 'analyst') => {
    if (demoType === 'admin') {
      setEmail('admin@threatatlas.io');
      setPassword('admin123');
    } else {
      setEmail('analyst@threatatlas.io');
      setPassword('analyst123');
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (value.length > 1) {
      // Handle paste of whole 6-digit code
      const pasted = value.replace(/\D/g, '').slice(0, 6).split('');
      const newDigits = [...otpDigits];
      pasted.forEach((char, i) => {
        if (index + i < 6) newDigits[index + i] = char;
      });
      setOtpDigits(newDigits);
      const nextIndex = Math.min(5, index + pasted.length);
      otpInputsRef.current[nextIndex]?.focus();
      return;
    }

    const digit = value.replace(/\D/g, '');
    const newDigits = [...otpDigits];
    newDigits[index] = digit;
    setOtpDigits(newDigits);

    // Auto-advance to next box
    if (digit && index < 5) {
      otpInputsRef.current[index + 1]?.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
      otpInputsRef.current[index - 1]?.focus();
    }
  };

  const handleOtpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const code = otpDigits.join('');
    if (code.length < 6) {
      setError('Please enter all 6 digits of the OTP code.');
      return;
    }

    setError(null);
    setLoading(true);
    const res = await verifyOtp(code);
    setLoading(false);
    if (!res.success) {
      setError(res.error || 'Invalid OTP code');
    }
  };

  const handleResend = async () => {
    if (countdown > 0) return;
    await resendOtp();
    setCountdown(60);
    setOtpResent(true);
    setTimeout(() => setOtpResent(false), 3000);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(5, 5, 12, 0.85)', backdropFilter: 'blur(16px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '20px',
    }}>
      {/* Modal Container */}
      <div
        className="glass-card animate-fade-in-up"
        style={{
          width: '100%', maxWidth: '440px', padding: '36px',
          background: 'rgba(10, 10, 22, 0.98)', border: '1px solid rgba(185,66,255,0.4)',
          borderRadius: '16px', boxShadow: '0 24px 64px rgba(0,0,0,0.9), 0 0 32px rgba(185,66,255,0.2)',
          position: 'relative',
        }}
      >
        {/* Close button */}
        <button
          onClick={closeAuthModal}
          style={{
            position: 'absolute', top: '16px', right: '16px',
            background: 'none', border: 'none', color: 'var(--on-surface-variant)',
            cursor: 'pointer', padding: '6px', borderRadius: '50%', display: 'flex',
          }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--on-surface)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--on-surface-variant)')}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>close</span>
        </button>

        {/* Logo / Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{
            width: '48px', height: '48px', borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(185,66,255,0.25), rgba(0,242,255,0.25))',
            border: '1px solid rgba(185,66,255,0.4)', display: 'inline-flex', alignItems: 'center',
            justifyContent: 'center', marginBottom: '12px',
          }}>
            <span className="material-symbols-outlined text-primary" style={{ fontSize: '28px' }}>
              {authMode === 'otp' ? 'mark_email_read' : 'lock'}
            </span>
          </div>
          <h2 className="font-headline-md text-on-surface" style={{ fontSize: '22px', marginBottom: '6px' }}>
            {authMode === 'login' && 'Analyst Sign In'}
            {authMode === 'signup' && 'Register New Account'}
            {authMode === 'otp' && '2FA OTP Verification'}
          </h2>
          <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
            {authMode === 'login' && 'Access advanced threat telemetry & higher scan quotas'}
            {authMode === 'signup' && 'Join ThreatAtlas with recognized security credentials'}
            {authMode === 'otp' && `Enter the 6-digit security code sent to ${pendingEmail}`}
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            padding: '10px 14px', borderRadius: '8px', marginBottom: '20px',
            background: 'rgba(255,0,60,0.1)', border: '1px solid rgba(255,0,60,0.3)',
            color: 'var(--secondary)', fontFamily: 'var(--font-mono)', fontSize: '12px',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>warning</span>
            <span>{error}</span>
          </div>
        )}

        {/* ── MODE 1: LOGIN ── */}
        {authMode === 'login' && (
          <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '6px', fontSize: '11px' }}>
                Analyst Email
              </label>
              <input
                type="email"
                required
                className="input-field font-data-mono"
                placeholder="admin@threatatlas.io"
                value={email}
                onChange={e => setEmail(e.target.value)}
                style={{ width: '100%', padding: '12px', fontSize: '13px' }}
              />
            </div>

            <div>
              <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '6px', fontSize: '11px' }}>
                Security Password
              </label>
              <input
                type="password"
                required
                className="input-field font-data-mono"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', padding: '12px', fontSize: '13px' }}
              />
            </div>

            {/* Quick Demo Login Preset Buttons */}
            <div style={{ padding: '10px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px', marginBottom: '6px' }}>
                Quick Demo Credentials:
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  onClick={() => handleQuickDemo('admin')}
                  style={{
                    flex: 1, padding: '4px 8px', borderRadius: '4px', background: 'rgba(185,66,255,0.1)',
                    border: '1px solid rgba(185,66,255,0.3)', color: 'var(--primary)', fontFamily: 'var(--font-mono)',
                    fontSize: '11px', cursor: 'pointer',
                  }}
                >
                  Admin Demo
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickDemo('analyst')}
                  style={{
                    flex: 1, padding: '4px 8px', borderRadius: '4px', background: 'rgba(0,242,255,0.1)',
                    border: '1px solid rgba(0,242,255,0.3)', color: '#22d3ee', fontFamily: 'var(--font-mono)',
                    fontSize: '11px', cursor: 'pointer',
                  }}
                >
                  Analyst Demo
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', padding: '12px', marginTop: '4px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              {loading ? <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span> : <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>login</span>}
              Continue to 2FA Verification
            </button>

            <div style={{ textAlign: 'center', marginTop: '8px', fontSize: '12px', color: 'var(--on-surface-variant)' }}>
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => setAuthMode('signup')}
                style={{ background: 'none', border: 'none', color: 'var(--primary)', fontWeight: 600, cursor: 'pointer', padding: 0 }}
              >
                Sign Up
              </button>
            </div>
          </form>
        )}

        {/* ── MODE 2: SIGN UP ── */}
        {authMode === 'signup' && (
          <form onSubmit={handleSignupSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '6px', fontSize: '11px' }}>
                Full Name
              </label>
              <input
                type="text"
                required
                className="input-field font-data-mono"
                placeholder="e.g. Elena Vance"
                value={name}
                onChange={e => setName(e.target.value)}
                style={{ width: '100%', padding: '10px 12px', fontSize: '13px' }}
              />
            </div>

            <div>
              <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '6px', fontSize: '11px' }}>
                Recognized Email Address
              </label>
              <input
                type="email"
                required
                className="input-field font-data-mono"
                placeholder="elena@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                style={{ width: '100%', padding: '10px 12px', fontSize: '13px' }}
              />
            </div>

            <div>
              <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '6px', fontSize: '11px' }}>
                Password (min. 6 chars)
              </label>
              <input
                type="password"
                required
                minLength={6}
                className="input-field font-data-mono"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', padding: '10px 12px', fontSize: '13px' }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', padding: '12px', marginTop: '6px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              {loading ? <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span> : <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>person_add</span>}
              Send 2FA Security Code
            </button>

            <div style={{ textAlign: 'center', marginTop: '8px', fontSize: '12px', color: 'var(--on-surface-variant)' }}>
              Already registered?{' '}
              <button
                type="button"
                onClick={() => setAuthMode('login')}
                style={{ background: 'none', border: 'none', color: 'var(--primary)', fontWeight: 600, cursor: 'pointer', padding: 0 }}
              >
                Sign In
              </button>
            </div>
          </form>
        )}

        {/* ── MODE 3: OTP 2FA VERIFICATION ── */}
        {authMode === 'otp' && (
          <form onSubmit={handleOtpSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Live Simulated OTP Chip */}
            <div style={{
              padding: '10px 14px', background: 'rgba(0,255,163,0.08)',
              border: '1px solid rgba(0,255,163,0.25)', borderRadius: '8px',
              textAlign: 'center',
            }}>
              <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginBottom: '2px' }}>
                Simulated Email OTP Dispatch:
              </div>
              <div className="font-data-mono" style={{ fontSize: '16px', color: 'var(--success)', fontWeight: 800, letterSpacing: '0.2em' }}>
                {demoOtp}
              </div>
            </div>

            {/* 6 Individual Digit Boxes */}
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
              {otpDigits.map((digit, idx) => (
                <input
                  key={idx}
                  ref={el => (otpInputsRef.current[idx] = el)}
                  type="text"
                  maxLength={1}
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={digit}
                  onChange={e => handleOtpChange(idx, e.target.value)}
                  onKeyDown={e => handleOtpKeyDown(idx, e)}
                  style={{
                    width: '46px', height: '52px', textAlign: 'center', fontSize: '20px', fontWeight: 800,
                    fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.5)',
                    border: `1px solid ${digit ? 'var(--primary)' : 'rgba(255,255,255,0.15)'}`,
                    borderRadius: '8px', color: '#ffffff', outline: 'none',
                    boxShadow: digit ? '0 0 12px var(--primary-dim)' : 'none',
                    transition: 'all 0.15s',
                  }}
                />
              ))}
            </div>

            <button
              type="submit"
              disabled={loading || otpDigits.join('').length < 6}
              className="btn-primary"
              style={{ width: '100%', padding: '12px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              {loading ? <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span> : <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>verified_user</span>}
              Verify & Complete Sign In
            </button>

            {/* Resend & Back options */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
              <button
                type="button"
                onClick={() => setAuthMode('login')}
                style={{ background: 'none', border: 'none', color: 'var(--on-surface-variant)', cursor: 'pointer', padding: 0 }}
              >
                ← Back
              </button>

              <button
                type="button"
                onClick={handleResend}
                disabled={countdown > 0}
                style={{
                  background: 'none', border: 'none',
                  color: countdown > 0 ? 'var(--on-surface-variant)' : 'var(--primary)',
                  fontWeight: 600, cursor: countdown > 0 ? 'default' : 'pointer', padding: 0,
                }}
              >
                {countdown > 0 ? `Resend OTP in ${countdown}s` : 'Resend OTP Code'}
              </button>
            </div>

            {otpResent && (
              <div style={{ textAlign: 'center', color: 'var(--success)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                ✓ Fresh security code generated!
              </div>
            )}
          </form>
        )}

      </div>
    </div>
  );
};
