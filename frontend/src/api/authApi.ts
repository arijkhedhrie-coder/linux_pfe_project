import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export interface LoginPayload {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export const loginRequest = async (
  payload: LoginPayload
): Promise<LoginResponse> => {
  const response = await axios.post<LoginResponse>(
    `${API_BASE}/auth/login`,
    payload
  );
  return response.data;
};