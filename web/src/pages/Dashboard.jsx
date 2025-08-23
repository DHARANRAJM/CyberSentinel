import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Shield, AlertTriangle, Activity, Users, Server, TrendingUp } from 'lucide-react';

const Dashboard = () => {
  const [stats, setStats] = useState({
    total_agents: 0,
    active_agents: 0,
    total_alerts: 0,
    open_alerts: 0,
    critical_alerts: 0,
    events_last_24h: 0,
    findings_last_24h: 0
  });
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [alertsResponse, agentsResponse] = await Promise.all([
        api.getAlerts({ limit: 5 }),
        api.getAgents({ limit: 10 })
      ]);

      setRecentAlerts(alertsResponse.data);
      
      // Calculate basic stats from the data
      const agents = agentsResponse.data;
      const alerts = alertsResponse.data;
      
      setStats({
        total_agents: agents.length,
        active_agents: agents.filter(a => {
          const lastSeen = new Date(a.last_seen);
          const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
          return lastSeen > fiveMinutesAgo;
        }).length,
        total_alerts: alerts.length,
        open_alerts: alerts.filter(a => a.status === 'open').length,
        critical_alerts: alerts.filter(a => a.priority === 'critical').length,
        events_last_24h: 0, // TODO: Implement
        findings_last_24h: 0 // TODO: Implement
      });
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({ title, value, icon: Icon, color = 'blue' }) => (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`p-3 rounded-full bg-${color}-100`}>
          <Icon className={`h-6 w-6 text-${color}-600`} />
        </div>
        <div className="ml-4">
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-semibold text-gray-900">{value}</p>
        </div>
      </div>
    </div>
  );

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 5: return 'text-red-600 bg-red-100';
      case 4: return 'text-orange-600 bg-orange-100';
      case 3: return 'text-yellow-600 bg-yellow-100';
      case 2: return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <Activity className="h-4 w-4" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Agents"
          value={stats.total_agents}
          icon={Server}
          color="blue"
        />
        <StatCard
          title="Active Agents"
          value={stats.active_agents}
          icon={Users}
          color="green"
        />
        <StatCard
          title="Open Alerts"
          value={stats.open_alerts}
          icon={AlertTriangle}
          color="yellow"
        />
        <StatCard
          title="Critical Alerts"
          value={stats.critical_alerts}
          icon={Shield}
          color="red"
        />
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Recent Alerts</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {recentAlerts.length > 0 ? (
            recentAlerts.map((alert) => (
              <div key={alert.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.finding?.severity || 1)}`}>
                      Severity {alert.finding?.severity || 1}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {alert.finding?.title || 'Unknown Alert'}
                      </p>
                      <p className="text-sm text-gray-500">
                        {alert.finding?.finding_type || 'Unknown Type'}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-gray-500">
                      {new Date(alert.created_at).toLocaleString()}
                    </p>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                      alert.status === 'open' ? 'bg-red-100 text-red-800' :
                      alert.status === 'acknowledged' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {alert.status}
                    </span>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="px-6 py-8 text-center">
              <Shield className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
              <p className="mt-1 text-sm text-gray-500">
                Your system is secure. No recent alerts to display.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
            <TrendingUp className="h-4 w-4 mr-2" />
            Generate Report
          </button>
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
            <AlertTriangle className="h-4 w-4 mr-2" />
            View All Alerts
          </button>
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
            <Server className="h-4 w-4 mr-2" />
            Manage Agents
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
