import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Alert, Box } from '@mui/material';

interface Props {
  children: ReactNode;
  /** Label shown above the error so the user knows which field failed. */
  label?: string;
}

interface State {
  error: Error | null;
  stack: string;
}

/**
 * Catches a render error inside a single field (e.g. a malformed date value)
 * and shows the message on screen instead of blanking the whole SPA.
 */
export class FieldErrorBoundary extends Component<Props, State> {
  state: State = { error: null, stack: '' };

  static getDerivedStateFromError(error: Error): State {
    return { error, stack: '' };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Field render error', error, info);
    this.setState({ stack: info.componentStack || '' });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Box sx={{ mb: 2 }}>
        <Alert severity="error">
          {this.props.label ? `${this.props.label}: ` : ''}This field could not be rendered.
          <Box component="pre" sx={{ whiteSpace: 'pre-wrap', mt: 1, fontSize: 12 }}>
            {this.state.error.message}
          </Box>
          {this.state.stack && (
            <Box component="pre" sx={{ whiteSpace: 'pre-wrap', mt: 1, fontSize: 11, color: 'text.secondary' }}>
              {this.state.stack}
            </Box>
          )}
        </Alert>
      </Box>
    );
  }
}