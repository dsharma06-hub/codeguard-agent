/**
 * CodeGuard Test Fixture: Clean production code with zero secrets.
 * All credentials are read from environment variables.
 */

export interface AppConfig {
  apiUrl: string;
  timeoutMs: number;
  environment: string;
  enableDebug: boolean;
}

export const config: AppConfig = {
  apiUrl: process.env.API_URL || "https://api.codeguard.internal",
  timeoutMs: 10000,
  environment: process.env.NODE_ENV || "production",
  enableDebug: process.env.DEBUG === "true",
};

export class AuthService {
  private tokenType: string = "Bearer";

  public getAuthorizationHeader(token: string): string {
    return `${this.tokenType} ${token}`;
  }

  public validateEndpoint(endpoint: string): boolean {
    const validEndpoints = [
      "/api/v1/auth/login",
      "/api/v1/auth/refresh",
      "/api/v1/auth/logout",
    ];
    return validEndpoints.includes(endpoint);
  }
}
