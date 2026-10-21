import type { AxiosError } from "axios";

type ErrorDetail = {
  detail?: unknown;
  // The backend's global handler wraps raised errors as {error:{code,message}};
  // FastAPI's own HTTPExceptions stay {detail}. Read both or the real reason
  // ("nmap is not installed…") collapses into a generic fallback.
  error?: { code?: number; message?: string };
};

/**
 * Turn a failed request into something the person can act on.
 *
 * Axios has no response at all when the server is unreachable, and every auth
 * screen used to collapse that case into "check your credentials" — so someone
 * opening the app from a phone, or after the backend stopped, was told their
 * password was wrong when nothing had been checked.
 */
export function describeRequestError(error: unknown, fallback: string): string {
  const err = error as AxiosError<ErrorDetail>;

  if (!err?.response) {
    return "Cannot reach the NetPulse server. It may be stopped, or this device may be on a different network.";
  }

  const detail = err.response.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail.trim();
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: unknown } | null;
    if (first && typeof first.msg === "string" && first.msg.trim()) return first.msg.trim();
  }

  const wrapped = err.response.data?.error?.message;
  if (typeof wrapped === "string" && wrapped.trim()) return wrapped.trim();

  switch (err.response.status) {
    case 401:
    case 403:
      return fallback;
    case 429:
      return "Too many attempts. Give it a moment and try again.";
    case 503:
      return "A required service is unavailable right now. Check the server log for details.";
    default:
      break;
  }

  if (err.response.status >= 500) {
    return "The server hit an error handling that request. Check the server log for details.";
  }

  return fallback;
}
