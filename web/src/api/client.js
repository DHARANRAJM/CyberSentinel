import axios from 'axios';

// Create axios instance with base configuration
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const api = {
  // Authentication
  login: (credentials) => apiClient.post('/auth/login', credentials),
  getProfile: () => apiClient.get('/auth/me'),

  // Alerts
  getAlerts: (params) => apiClient.get('/api/alerts', { params }),
  getAlert: (id) => apiClient.get(`/api/alerts/${id}`),
  updateAlert: (id, data) => apiClient.patch(`/api/alerts/${id}`, data),

  // Events
  getEvents: (params) => apiClient.get('/api/events', { params }),

  // Agents
  getAgents: (params) => apiClient.get('/api/agents', { params }),

  // Rules
  getRules: () => apiClient.get('/api/rules'),

  // Reports
  getReports: () => apiClient.get('/api/reports'),
};
