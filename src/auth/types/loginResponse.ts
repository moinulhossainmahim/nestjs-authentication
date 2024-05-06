export type LoginResponse = {
  accessToken: string;
  refreshToken: string;
  picture: string;
  fullName: string;
  isGoogleLogin: boolean;
  email: string;
};
