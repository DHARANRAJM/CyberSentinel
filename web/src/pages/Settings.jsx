import React from 'react';
import { Settings as SettingsIcon, User, Shield, Bell } from 'lucide-react';

const Settings = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center space-x-3 mb-4">
            <User className="h-6 w-6 text-gray-400" />
            <h2 className="text-lg font-medium text-gray-900">User Profile</h2>
          </div>
          <p className="text-sm text-gray-500">Manage your account settings and preferences.</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Shield className="h-6 w-6 text-gray-400" />
            <h2 className="text-lg font-medium text-gray-900">Security</h2>
          </div>
          <p className="text-sm text-gray-500">Configure security settings and API keys.</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Bell className="h-6 w-6 text-gray-400" />
            <h2 className="text-lg font-medium text-gray-900">Notifications</h2>
          </div>
          <p className="text-sm text-gray-500">Set up alert notifications and integrations.</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center space-x-3 mb-4">
            <SettingsIcon className="h-6 w-6 text-gray-400" />
            <h2 className="text-lg font-medium text-gray-900">System</h2>
          </div>
          <p className="text-sm text-gray-500">Configure system-wide settings and preferences.</p>
        </div>
      </div>
    </div>
  );
};

export default Settings;
