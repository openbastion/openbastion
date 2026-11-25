import { Component, type ErrorInfo, type ReactNode } from "react";

export type AppErrorBoundaryProps = {
  children: ReactNode;
  // What replaces the subtree after an error. A function receives the error and a `reset`.
  fallback: ReactNode | ((error: Error, reset: () => void) => ReactNode);
  onError?: (error: Error, info: ErrorInfo) => void;
  // The boundary clears itself when one of these changes (the route, for instance), so that a
  // failed screen does not keep the next one hostage.
  resetKeys?: readonly unknown[];
};

type State = { error: Error | null };

const changed = (a: readonly unknown[] = [], b: readonly unknown[] = []) =>
  a.length !== b.length || a.some((value, index) => !Object.is(value, b[index]));

// An error in one screen must not blank the shell (ADR-0137 §5, one boundary per route). It
// reports to the caller and never prints the error itself: a message may carry sensitive text.
export class AppErrorBoundary extends Component<AppErrorBoundaryProps, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    this.props.onError?.(error, info);
  }

  componentDidUpdate(previous: AppErrorBoundaryProps) {
    if (this.state.error && changed(previous.resetKeys, this.props.resetKeys)) this.reset();
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const { fallback } = this.props;
    return typeof fallback === "function" ? fallback(error, this.reset) : fallback;
  }
}
