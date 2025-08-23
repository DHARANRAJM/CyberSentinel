import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Server, Wifi, WifiOff } from 'lucide-react';

const Agents = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = async () => {
    try {
      const response = await api.getAgents();
      setAgents(response.data);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    } finally {
      setLoading(false);
    }
  };

  const getAgentStatus = (lastSeen) => {
    if (!lastSeen) return 'offline';
    const lastSeenDate = new Date(lastSeen);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return lastSeenDate > fiveMinutesAgo ? 'online' : 'offline';
  };

  const getStatusColor = (status) => {
    return status === 'online' ? 'text-green-600' : 'text-red-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Security Agents</h1>
        <div className="text-sm text-gray-500">
          {agents.filter(a => getAgentStatus(a.last_seen) === 'online').length} of {agents.length} agents online
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {agents.map((agent) => {
          const status = getAgentStatus(agent.last_seen);
          const StatusIcon = status === 'online' ? Wifi : WifiOff;
          
          return (
            <div key={agent.id} className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Server className="h-8 w-8 text-gray-400" />
                  <div>
                    <h3 className="text-lg font-medium text-gray-900">{agent.name}</h3>
                    <p className="text-sm text-gray-500">{agent.hostname}</p>
                  </div>
                </div>
                <StatusIcon className={`h-5 w-5 ${getStatusColor(status)}`} />
              </div>
              
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">OS:</span>
                  <span className="text-gray-900">{agent.os_type} {agent.os_version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">IP:</span>
                  <span className="text-gray-900">{agent.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Version:</span>
                  <span className="text-gray-900">{agent.version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Seen:</span>
                  <span className="text-gray-900">
                    {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'Never'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Status:</span>
                  <span className={`font-medium ${getStatusColor(status)}`}>
                    {status.charAt(0).toUpperCase() + status.slice(1)}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {agents.length === 0 && (
        <div className="text-center py-12">
          <Server className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No agents</h3>
          <p className="mt-1 text-sm text-gray-500">No security agents are currently registered.</p>
        </div>
      )}
    </div>
  );
};

export default Agents;
