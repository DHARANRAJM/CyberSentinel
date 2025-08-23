import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Activity, Filter } from 'lucide-react';

const Events = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ event_type: '', severity: '' });

  useEffect(() => {
    fetchEvents();
  }, [filter]);

  const fetchEvents = async () => {
    try {
      const params = {};
      if (filter.event_type) params.event_type = filter.event_type;
      if (filter.severity) params.severity = parseInt(filter.severity);
      
      const response = await api.getEvents(params);
      setEvents(response.data);
    } catch (error) {
      console.error('Failed to fetch events:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 5: return 'bg-red-100 text-red-800';
      case 4: return 'bg-orange-100 text-orange-800';
      case 3: return 'bg-yellow-100 text-yellow-800';
      case 2: return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
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
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Security Events</h1>
        <div className="flex items-center space-x-4">
          <select
            value={filter.event_type}
            onChange={(e) => setFilter({ ...filter, event_type: e.target.value })}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            <option value="auth.fail">Auth Failures</option>
            <option value="port.snapshot">Port Snapshots</option>
            <option value="process.snapshot">Process Snapshots</option>
          </select>
          <select
            value={filter.severity}
            onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="">All Severities</option>
            <option value="1">Severity 1</option>
            <option value="2">Severity 2</option>
            <option value="3">Severity 3</option>
            <option value="4">Severity 4</option>
            <option value="5">Severity 5</option>
          </select>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg">
        {events.length > 0 ? (
          <div className="divide-y divide-gray-200">
            {events.map((event) => (
              <div key={event.id} className="p-6 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(event.severity)}`}>
                        Severity {event.severity}
                      </span>
                      <span className="text-sm text-gray-500">{event.event_type}</span>
                    </div>
                    <div className="text-sm text-gray-600">
                      <p><strong>Source:</strong> {event.source || 'Unknown'}</p>
                      <p><strong>Timestamp:</strong> {new Date(event.timestamp).toLocaleString()}</p>
                    </div>
                    {event.payload && Object.keys(event.payload).length > 0 && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-sm text-blue-600 hover:text-blue-800">
                          View Payload
                        </summary>
                        <pre className="mt-2 text-xs bg-gray-100 p-2 rounded overflow-x-auto">
                          {JSON.stringify(event.payload, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <Activity className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No events</h3>
            <p className="mt-1 text-sm text-gray-500">No security events to display.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Events;
