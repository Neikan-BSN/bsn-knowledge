"""
Performance monitoring and optimization service for BSN Knowledge API
"""
import asyncio
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


@dataclass
class RequestMetrics:
    """Individual request metrics"""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    timestamp: datetime
    error: Optional[str] = None
    cache_hit: bool = False


@dataclass
class EndpointStats:
    """Aggregated statistics for an endpoint"""
    endpoint: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    p95_response_time: float = 0.0
    cache_hit_rate: float = 0.0
    recent_response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    last_updated: datetime = field(default_factory=datetime.now)


class PerformanceMonitor:
    """Enhanced performance monitoring for API endpoints and services"""
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics: List[RequestMetrics] = []
        self.endpoint_stats: Dict[str, EndpointStats] = defaultdict(EndpointStats)
        self.system_metrics = {
            "total_requests": 0,
            "average_response_time": 0.0,
            "error_rate": 0.0,
            "cache_hit_rate": 0.0,
            "slow_requests_count": 0,
            "last_cleanup": datetime.now()
        }
        self.slow_request_threshold = 0.5  # 500ms
        self.alerts = []
        
        # Start background cleanup task
        self._cleanup_task = None
        
    async def start_monitoring(self):
        """Start background monitoring tasks"""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop background monitoring tasks"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Performance monitoring stopped")
    
    def record_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        response_time: float,
        error: Optional[str] = None,
        cache_hit: bool = False
    ):
        """Record a request's performance metrics"""
        
        # Create request metrics
        metric = RequestMetrics(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time=response_time,
            timestamp=datetime.now(),
            error=error,
            cache_hit=cache_hit
        )
        
        self.metrics.append(metric)
        self._update_endpoint_stats(metric)
        self._update_system_metrics(metric)
        self._check_for_alerts(metric)
        
        # Log slow requests
        if response_time > self.slow_request_threshold:
            logger.warning(f"Slow request: {method} {endpoint} took {response_time:.3f}s")
    
    def _update_endpoint_stats(self, metric: RequestMetrics):
        """Update aggregated endpoint statistics"""
        endpoint_key = f"{metric.method} {metric.endpoint}"
        stats = self.endpoint_stats[endpoint_key]
        
        if stats.endpoint == "":  # First time initialization
            stats.endpoint = endpoint_key
        
        stats.total_requests += 1
        stats.recent_response_times.append(metric.response_time)
        
        if metric.status_code < 400:
            stats.successful_requests += 1
        else:
            stats.failed_requests += 1
        
        # Update response time statistics
        stats.min_response_time = min(stats.min_response_time, metric.response_time)
        stats.max_response_time = max(stats.max_response_time, metric.response_time)
        
        # Calculate running average
        total_time = stats.average_response_time * (stats.total_requests - 1) + metric.response_time
        stats.average_response_time = total_time / stats.total_requests
        
        # Calculate P95 from recent response times
        if len(stats.recent_response_times) >= 20:
            sorted_times = sorted(list(stats.recent_response_times))
            p95_index = int(len(sorted_times) * 0.95)
            stats.p95_response_time = sorted_times[p95_index]
        
        # Update cache hit rate
        cache_hits = sum(1 for m in self.metrics 
                        if m.endpoint == metric.endpoint and m.cache_hit 
                        and (datetime.now() - m.timestamp).seconds < 3600)
        total_cacheable = sum(1 for m in self.metrics 
                            if m.endpoint == metric.endpoint and m.method == "GET"
                            and (datetime.now() - m.timestamp).seconds < 3600)
        
        if total_cacheable > 0:
            stats.cache_hit_rate = (cache_hits / total_cacheable) * 100
        
        stats.last_updated = datetime.now()
    
    def _update_system_metrics(self, metric: RequestMetrics):
        """Update system-wide performance metrics"""
        self.system_metrics["total_requests"] += 1
        
        # Update average response time
        total_time = (self.system_metrics["average_response_time"] * 
                     (self.system_metrics["total_requests"] - 1) + metric.response_time)
        self.system_metrics["average_response_time"] = total_time / self.system_metrics["total_requests"]
        
        # Update error rate
        error_count = sum(1 for m in self.metrics if m.status_code >= 400)
        self.system_metrics["error_rate"] = (error_count / len(self.metrics)) * 100
        
        # Update cache hit rate
        cache_hits = sum(1 for m in self.metrics if m.cache_hit)
        total_cacheable = sum(1 for m in self.metrics if m.method == "GET")
        if total_cacheable > 0:
            self.system_metrics["cache_hit_rate"] = (cache_hits / total_cacheable) * 100
        
        # Count slow requests
        if metric.response_time > self.slow_request_threshold:
            self.system_metrics["slow_requests_count"] += 1
    
    def _check_for_alerts(self, metric: RequestMetrics):
        """Check if this metric triggers any alerts"""
        alerts_to_add = []
        
        # Slow request alert
        if metric.response_time > self.slow_request_threshold:
            alerts_to_add.append({
                "type": "slow_request",
                "endpoint": metric.endpoint,
                "response_time": metric.response_time,
                "threshold": self.slow_request_threshold,
                "timestamp": metric.timestamp
            })
        
        # Error alert
        if metric.status_code >= 500:
            alerts_to_add.append({
                "type": "server_error",
                "endpoint": metric.endpoint,
                "status_code": metric.status_code,
                "error": metric.error,
                "timestamp": metric.timestamp
            })
        
        # High error rate alert (more than 5% errors in last 100 requests)
        recent_metrics = [m for m in self.metrics[-100:]]
        if len(recent_metrics) >= 50:
            error_count = sum(1 for m in recent_metrics if m.status_code >= 400)
            error_rate = (error_count / len(recent_metrics)) * 100
            
            if error_rate > 5.0:
                alerts_to_add.append({
                    "type": "high_error_rate",
                    "error_rate": error_rate,
                    "threshold": 5.0,
                    "sample_size": len(recent_metrics),
                    "timestamp": metric.timestamp
                })
        
        # Add new alerts (limit to 100 most recent)
        self.alerts.extend(alerts_to_add)
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system-wide performance metrics"""
        return {
            **self.system_metrics,
            "metrics_count": len(self.metrics),
            "endpoints_monitored": len(self.endpoint_stats),
            "recent_alerts_count": len([a for a in self.alerts 
                                      if (datetime.now() - a["timestamp"]).seconds < 3600])
        }
    
    def get_endpoint_metrics(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get per-endpoint performance metrics"""
        stats_list = []
        
        for endpoint, stats in self.endpoint_stats.items():
            stats_dict = {
                "endpoint": stats.endpoint,
                "total_requests": stats.total_requests,
                "successful_requests": stats.successful_requests,
                "failed_requests": stats.failed_requests,
                "success_rate": (stats.successful_requests / max(1, stats.total_requests)) * 100,
                "average_response_time": stats.average_response_time,
                "min_response_time": stats.min_response_time,
                "max_response_time": stats.max_response_time,
                "p95_response_time": stats.p95_response_time,
                "cache_hit_rate": stats.cache_hit_rate,
                "last_updated": stats.last_updated.isoformat()
            }
            stats_list.append(stats_dict)
        
        # Sort by total requests (most active first)
        stats_list.sort(key=lambda x: x["total_requests"], reverse=True)
        
        return stats_list[:limit] if limit else stats_list
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        alerts = self.alerts[-limit:]
        
        if severity:
            severity_map = {
                "high": ["server_error", "high_error_rate"],
                "medium": ["slow_request"],
                "low": []
            }
            filtered_types = severity_map.get(severity, [])
            alerts = [a for a in alerts if a["type"] in filtered_types]
        
        # Convert timestamps to ISO format
        for alert in alerts:
            alert["timestamp"] = alert["timestamp"].isoformat()
        
        return alerts
    
    def get_slowest_endpoints(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the slowest endpoints by average response time"""
        endpoint_list = []
        
        for endpoint, stats in self.endpoint_stats.items():
            if stats.total_requests >= 10:  # Only include endpoints with sufficient data
                endpoint_list.append({
                    "endpoint": stats.endpoint,
                    "average_response_time": stats.average_response_time,
                    "p95_response_time": stats.p95_response_time,
                    "total_requests": stats.total_requests
                })
        
        endpoint_list.sort(key=lambda x: x["average_response_time"], reverse=True)
        return endpoint_list[:limit]
    
    async def _periodic_cleanup(self):
        """Periodically clean up old metrics to prevent memory bloat"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self._cleanup_old_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {str(e)}")
    
    async def _cleanup_old_metrics(self):
        """Remove metrics older than retention period"""
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        
        # Filter out old metrics
        old_count = len(self.metrics)
        self.metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
        new_count = len(self.metrics)
        
        if old_count > new_count:
            logger.info(f"Cleaned up {old_count - new_count} old metrics")
            self.system_metrics["last_cleanup"] = datetime.now()
        
        # Clean up old alerts
        alert_cutoff = datetime.now() - timedelta(hours=24)
        old_alert_count = len(self.alerts)
        self.alerts = [a for a in self.alerts if a["timestamp"] > alert_cutoff]
        
        if old_alert_count > len(self.alerts):
            logger.info(f"Cleaned up {old_alert_count - len(self.alerts)} old alerts")


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


async def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance"""
    if performance_monitor._cleanup_task is None:
        await performance_monitor.start_monitoring()
    return performance_monitor