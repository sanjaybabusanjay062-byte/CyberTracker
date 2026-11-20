import math
from flask import render_template, jsonify, request
from flask_login import login_required
from app.attack_graph import attack_graph_bp
from app.models import LogRecord, ThreatAlert, Case
from app import db


@attack_graph_bp.route('/attack-graph')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('attack_graph/index.html', title='Attack Reconstruction Graph', cases=cases)


@attack_graph_bp.route('/api/attack-graph/data')
@login_required
def graph_data():
    case_id = request.args.get('case_id')

    q = LogRecord.query
    if case_id:
        q = q.filter(LogRecord.case_id == int(case_id))

    records = q.order_by(LogRecord.timestamp.asc()).limit(500).all()
    alerts = ThreatAlert.query
    if case_id:
        alerts = alerts.filter(ThreatAlert.case_id == int(case_id))
    alerts = alerts.all()

    nodes = {}
    edges = []

    suspicious_ips = {a.source_ip for a in alerts if a.source_ip}
    suspicious_users = {a.username for a in alerts if a.username}

    def add_node(node_id, node_type, label, is_suspicious=False, first_seen=None, desc=None):
        if node_id not in nodes:
            nodes[node_id] = {
                'id': node_id,
                'type': node_type,
                'label': label,
                'is_suspicious': is_suspicious,
                'first_seen': first_seen or 'Recent Telemetry',
                'description': desc or f'Forensic {node_type.upper()} entity observed in session logs.',
                'degree': 0,
                'x': None,
                'y': None
            }
        else:
            if is_suspicious:
                nodes[node_id]['is_suspicious'] = True
            if desc and not nodes[node_id].get('has_custom_desc'):
                nodes[node_id]['description'] = desc
                nodes[node_id]['has_custom_desc'] = True

    for rec in records:
        ts_str = rec.timestamp.strftime('%Y-%m-%d %H:%M:%S') if rec.timestamp else 'N/A'

        # IP Node
        if rec.source_ip:
            is_sus = rec.source_ip in suspicious_ips or rec.is_suspicious
            desc = f"Observed in {rec.event_type} event. Suspect ingress/traffic vector." if is_sus else "Internal/standard IP endpoint."
            add_node(f'ip_{rec.source_ip}', 'ip', rec.source_ip, is_sus, ts_str, desc)

        # Destination / Host Node
        if rec.destination_ip and rec.destination_ip != rec.source_ip:
            add_node(f'sys_{rec.destination_ip}', 'sys', rec.destination_ip, False, ts_str, "Target destination endpoint / infrastructure host.")

        # User Node
        if rec.username:
            is_sus_u = rec.username in suspicious_users or rec.is_suspicious
            desc = f"Account involved in suspicious activity or off-hours logon." if is_sus_u else "Standard principal account."
            add_node(f'user_{rec.username}', 'user', rec.username, is_sus_u, ts_str, desc)

        # Event Node for high/critical events
        if rec.severity in ('high', 'critical') or rec.is_suspicious:
            ev_id = f'event_{rec.id}'
            add_node(ev_id, 'event', rec.event_type, rec.is_suspicious, ts_str, rec.event_description)
            if rec.source_ip:
                edges.append({
                    'from': f'ip_{rec.source_ip}',
                    'to': ev_id,
                    'type': 'confirmed',
                    'label': 'originates'
                })
            if rec.username:
                edges.append({
                    'from': f'user_{rec.username}',
                    'to': ev_id,
                    'type': 'confirmed',
                    'label': 'executed'
                })
            if rec.destination_ip and rec.destination_ip != rec.source_ip:
                edges.append({
                    'from': ev_id,
                    'to': f'sys_{rec.destination_ip}',
                    'type': 'confirmed',
                    'label': 'targets'
                })

        # Relationship IP -> User
        if rec.source_ip and rec.username:
            is_confirmed = rec.event_type in ('login_success', 'login_failure')
            edge_type = 'confirmed' if is_confirmed else 'inferred'
            edge_label = rec.event_type.replace('_', ' ')
            
            existing = any(e['from'] == f'ip_{rec.source_ip}' and e['to'] == f'user_{rec.username}' for e in edges)
            if not existing:
                edges.append({
                    'from': f'ip_{rec.source_ip}',
                    'to': f'user_{rec.username}',
                    'type': edge_type,
                    'label': edge_label
                })

    # Update degrees
    for edge in edges:
        if edge['from'] in nodes:
            nodes[edge['from']]['degree'] += 1
        if edge['to'] in nodes:
            nodes[edge['to']]['degree'] += 1

    # Circular Layout
    node_list = list(nodes.values())
    n = len(node_list)
    cx, cy = 480, 300
    r = min(320, max(180, 20 * n))
    for i, node in enumerate(node_list):
        angle = (2 * math.pi * i) / max(n, 1)
        node['x'] = round(cx + r * math.cos(angle), 1)
        node['y'] = round(cy + r * math.sin(angle), 1)

    return jsonify({
        'nodes': node_list,
        'edges': edges,
        'stats': {
            'total_nodes': len(node_list),
            'total_edges': len(edges),
            'suspicious_nodes': sum(1 for nd in node_list if nd['is_suspicious'])
        }
    })
