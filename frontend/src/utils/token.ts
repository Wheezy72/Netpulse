/**
 * The stored access token, wherever "Remember me" put it.
 *
 * Checked: localStorage (30-day token). Unchecked: sessionStorage (60-minute
 * token that dies with the browser). Anything that needs the token outside the
 * auth store — the SSH terminal socket, the scan output stream — has to look in
 * both, otherwise an unchecked sign-in silently appears to be logged out.
 */
export function getStoredToken(): string {
  return localStorage.getItem("np-token") || sessionStorage.getItem("np-token") || "";
}
