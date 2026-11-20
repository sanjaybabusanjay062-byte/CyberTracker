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

    def add_node(node_id, node_type, label, is_suspicious=False):
        if node_id not in nodes:
            nodes[node_id] = {
                'id': node_id,
                'type': node_type,
                'label': label,
                'is_suspicious': is_suspicious,
                'x': None, 'y': None
            }
        elif is_suspicious:
            nodes[node_id]['is_suspicious'] = True

    for rec in records:
        # Add IP node
        if rec.source_ip:
            is_sus = rec.source_ip in suspicious_ips or rec.is_suspicious
            add_node(f'ip_{rec.source_ip}', 'ip', rec.source_ip, is_sus)

        # Add user node
        if rec.username:
            add_node(f'user_{rec.username}', 'user', rec.username)

        # Add event node for high/critical events
        if rec.severity in ('high', 'critical'):
            ev_id = f'event_{rec.id}'
            add_node(ev_id, 'event', rec.event_type, rec.is_suspicious)
            if rec.source_ip:
                edge_type = 'confirmed' if not rec.is_suspicious else 'confirmed'
                edges.append({
                    'from': f'ip_{rec.source_ip}',
                    'to': ev_id,
                    'type': edge_type,
                    'label': rec.event_type
                })
            if rec.username:
                edges.append({
                    'from': f'user_{rec.username}',
                    'to': ev_id,
                    'type': 'confirmed',
                    'label': 'performed'
                })

        # IP -> User edge
        if rec.source_ip and rec.username:
            edge_type = 'confirmed' if rec.event_type in ('login_success', 'login_failure') else 'inferred'
            edge_key = f'ip_{rec.source_ip}->user_{rec.username}'
            existing = any(
                e['from'] == f'ip_{rec.source_ip}' and e['to'] == f'user_{rec.username}'
                for e in edges
            )
            if not existing:
                edges.append({
                    'from': f'ip_{rec.source_ip}',
                    'to': f'user_{rec.username}',
                    'type': edge_type,
                    'label': rec.event_type
                })

    # Layout: simple circular positioning
    import math
    node_list = list(nodes.values())
    n = len(node_list)
    cx, cy, r = 400, 300, 220
    for i, node in enumerate(node_list):
        angle = (2 * math.pi * i) / max(n, 1)
        node['x'] = cx + r * math.cos(angle)
        node['y'] = cy + r * math.sin(angle)

    return jsonify({
        'nodes': node_list,
        'edges': edges,
        'stats': {
            'total_nodes': len(node_list),
            'total_edges': len(edges),
            'suspicious_nodes': sum(1 for nd in node_list if nd['is_suspicious'])
        }
    })
