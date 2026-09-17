import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ThreatAtlas ErrorBoundary caught an unhandled render exception:', error, errorInfo);
    this.setState({ error, errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.href = '/';
  };

  private handleReload = () => {
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#060809',
            color: '#f8fafc',
            padding: '24px',
            fontFamily: 'var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif)',
          }}
        >
          <div
            style={{
              maxWidth: '620px',
              width: '100%',
              background: '#0d131f',
              border: '1px solid #1e293b',
              borderRadius: '12px',
              padding: '36px 32px',
              textAlign: 'center',
              boxShadow: '0 20px 40px rgba(0,0,0,0.6), 0 0 30px rgba(255,42,95,0.08)',
            }}
          >
            <div
              style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'rgba(255, 42, 95, 0.12)',
                border: '1px solid rgba(255, 42, 95, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 20px',
                color: '#ff2a5f',
              }}
            >
              <AlertTriangle size={32} />
            </div>

            <h2
              style={{
                fontSize: '22px',
                fontWeight: 700,
                color: '#f1f5f9',
                marginBottom: '10px',
                letterSpacing: '-0.02em',
              }}
            >
              Application Interface Fault
            </h2>

            <p
              style={{
                fontSize: '14px',
                color: '#94a3b8',
                lineHeight: 1.6,
                marginBottom: '20px',
              }}
            >
              ThreatAtlas encountered an unexpected rendering error. The security telemetry pipeline was preserved.
            </p>

            {this.state.error && (
              <div
                style={{
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  marginBottom: '24px',
                  textAlign: 'left',
                  fontSize: '12px',
                  color: '#fb7185',
                  fontFamily: 'var(--font-mono, monospace)',
                  overflowX: 'auto',
                  maxHeight: '120px',
                }}
              >
                {this.state.error.message || String(this.state.error)}
              </div>
            )}

            <div
              style={{
                display: 'flex',
                gap: '12px',
                justifyContent: 'center',
                flexWrap: 'wrap',
              }}
            >
              <button
                onClick={this.handleReload}
                style={{
                  background: 'rgba(255, 69, 0, 0.12)',
                  border: '1px solid var(--brand)',
                  color: 'var(--brand)',
                  borderRadius: '8px',
                  padding: '10px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'all 0.15s ease',
                }}
              >
                <RefreshCw size={15} />
                Reload View
              </button>

              <button
                onClick={this.handleReset}
                style={{
                  background: 'rgba(255,255,255,0.04)',
                  border: '1px solid #334155',
                  color: '#cbd5e1',
                  borderRadius: '8px',
                  padding: '10px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'all 0.15s ease',
                }}
              >
                <Home size={15} />
                Return to Scanner
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
