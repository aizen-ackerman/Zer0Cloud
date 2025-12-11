from flask import Flask, render_template, request, jsonify
import boto3
import json
from datetime import datetime
import time
import random
import threading
import os
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError

app = Flask(__name__)


scan_sessions = {}
settings_store = {
    'aws_access_key': None,
    'aws_secret_key': None,
    'aws_session_token': None,
    'aws_region': 'us-east-1'
}


def _update_session(session_id: str, **kwargs) -> None:
    session = scan_sessions.get(session_id)
    if not session:
        return
    session.update(kwargs)


def _append_findings(session_id: str, new_findings: List[Dict[str, Any]]) -> None:
    session = scan_sessions.get(session_id)
    if not session:
        return
    session_findings = session.get('findings', [])
    session_findings.extend(new_findings)
    session['findings'] = session_findings

def scan_aws_misconfigurations(credentials_id, scan_scope=None):
    findings = []
    
    try:

        s3 = boto3.client('s3')
        ec2 = boto3.client('ec2')
        iam = boto3.client('iam')
        rds = boto3.client('rds')
        

        if not scan_scope or 's3' in scan_scope:
            try:
                buckets = s3.list_buckets()
                
                for bucket in buckets['Buckets']:
                    try:

                        acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                        if any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' 
                               for grant in acl['Grants']):
                            findings.append({
                                'type': 'S3_PUBLIC_ACCESS', 
                                'resource': bucket['Name'],
                                'severity': 'HIGH',
                                'description': 'S3 bucket is publicly accessible',
                                'timestamp': datetime.now().isoformat()
                            })
                        

                        try:
                            policy = s3.get_bucket_policy(Bucket=bucket['Name'])
                            if '"Principal": "*"' in policy['Policy']:
                                findings.append({
                                    'type': 'S3_PUBLIC_POLICY',
                                    'resource': bucket['Name'],
                                    'severity': 'HIGH',
                                    'description': 'S3 bucket has public access policy',
                                    'timestamp': datetime.now().isoformat()
                                })
                        except:
                            pass
                            
                    except Exception as e:
                        findings.append({
                            'type': 'S3_ACCESS_ERROR',
                            'resource': bucket['Name'],
                            'severity': 'MEDIUM',
                            'description': f'Unable to access bucket: {str(e)}',
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                findings.append({
                    'type': 'S3_LIST_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to list S3 buckets: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'ec2' in scan_scope:
            try:
                instances = ec2.describe_instances()
                
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:

                        if instance['State']['Name'] == 'running':

                            for sg in instance['SecurityGroups']:
                                try:
                                    sg_rules = ec2.describe_security_group_rules(
                                        Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}]
                                    )
                                    
                                    for rule in sg_rules['SecurityGroupRules']:
                                        if rule.get('IpProtocol') == '-1' and rule.get('CidrIpv4') == '0.0.0.0/0':
                                            findings.append({
                                                'type': 'EC2_OPEN_SECURITY_GROUP',
                                                'resource': f"{instance['InstanceId']} ({sg['GroupName']})",
                                                'severity': 'HIGH',
                                                'description': 'EC2 instance has security group allowing all traffic',
                                                'timestamp': datetime.now().isoformat()
                                            })
                                            break
                                except:
                                    pass
            except Exception as e:
                findings.append({
                    'type': 'EC2_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan EC2 instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'iam' in scan_scope:
            try:
                users = iam.list_users()
                
                for user in users['Users']:
                    try:
                        policies = iam.list_attached_user_policies(UserName=user['UserName'])
                        
                        for policy in policies['AttachedPolicies']:
                            if policy['PolicyName'] in ['AdministratorAccess', 'PowerUserAccess']:
                                findings.append({
                                    'type': 'IAM_OVERPRIVILEGED',
                                    'resource': user['UserName'],
                                    'severity': 'HIGH',
                                    'description': f'User has {policy["PolicyName"]} policy attached',
                                    'timestamp': datetime.now().isoformat()
                                })
                    except:
                        pass
            except Exception as e:
                findings.append({
                    'type': 'IAM_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan IAM users: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
        

        if not scan_scope or 'rds' in scan_scope:
            try:
                instances = rds.describe_db_instances()
                
                for instance in instances['DBInstances']:
                    if instance.get('PubliclyAccessible', False):
                        findings.append({
                            'type': 'RDS_PUBLIC_ACCESS',
                            'resource': instance['DBInstanceIdentifier'],
                            'severity': 'HIGH',
                            'description': 'RDS instance is publicly accessible',
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                findings.append({
                    'type': 'RDS_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan RDS instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                })
                
    except Exception as e:
        findings.append({
            'type': 'CONNECTION_ERROR',
            'severity': 'MEDIUM',
            'description': f'Unable to connect to AWS: {str(e)}',
            'timestamp': datetime.now().isoformat()
        })
    
    return findings


def run_scan_session(session_id: str, credentials_id: str, scan_scope: List[str] | None, scan_depth: str) -> None:
    try:
        services = ['s3', 'ec2', 'iam', 'rds']
        if scan_scope:
            normalized_scope = set(scan_scope)
            if 'vpc' in normalized_scope:
                normalized_scope.add('ec2')
            services = [s for s in services if s in normalized_scope]

        total_steps = max(len(services), 1)
        step_index = 0

        _update_session(session_id, status='running', progress=0, current_stage='Initializing')

        client_kwargs = {}
        region_name = settings_store.get('aws_region') or 'us-east-1'
        if region_name:
            client_kwargs['region_name'] = region_name
        if settings_store.get('aws_access_key') and settings_store.get('aws_secret_key'):
            client_kwargs['aws_access_key_id'] = settings_store.get('aws_access_key')
            client_kwargs['aws_secret_access_key'] = settings_store.get('aws_secret_key')
        if settings_store.get('aws_session_token'):
            client_kwargs['aws_session_token'] = settings_store.get('aws_session_token')

        _update_session(session_id, current_stage='Validating AWS credentials')
        credentials_valid = True
        credential_error_msg = None
        
        try:
            test_client = boto3.client('sts', **client_kwargs)
            test_client.get_caller_identity()
        except NoCredentialsError:
            credentials_valid = False
            credential_error_msg = 'No AWS credentials found. Please configure AWS credentials using environment variables, AWS CLI (aws configure), or IAM role.'
            _append_findings(session_id, [{
                'type': 'CONNECTION_ERROR',
                'severity': 'HIGH',
                'description': credential_error_msg,
                'timestamp': datetime.now().isoformat()
            }])
        except ClientError as e:
            credentials_valid = False
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            credential_error_msg = f'AWS authentication failed: {error_message} ({error_code}). Please check your credentials.'
            _append_findings(session_id, [{
                'type': 'CONNECTION_ERROR',
                'severity': 'HIGH',
                'description': credential_error_msg,
                'timestamp': datetime.now().isoformat()
            }])
        except Exception as e:
            credentials_valid = False
            credential_error_msg = f'Unable to connect to AWS: {str(e)}. Please verify your AWS credentials and network connection.'
            _append_findings(session_id, [{
                'type': 'CONNECTION_ERROR',
                'severity': 'HIGH',
                'description': credential_error_msg,
                'timestamp': datetime.now().isoformat()
            }])
        
        if not credentials_valid:
            if not scan_scope or 's3' in services:
                _append_findings(session_id, [{
                    'type': 'S3_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'resource': 'N/A',
                    'description': f'Unable to scan S3 buckets: {credential_error_msg}',
                    'timestamp': datetime.now().isoformat()
                }])
            if not scan_scope or 'ec2' in services:
                _append_findings(session_id, [{
                    'type': 'EC2_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'resource': 'N/A',
                    'description': f'Unable to scan EC2 instances: {credential_error_msg}',
                    'timestamp': datetime.now().isoformat()
                }])
            if not scan_scope or 'iam' in services:
                _append_findings(session_id, [{
                    'type': 'IAM_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'resource': 'N/A',
                    'description': f'Unable to scan IAM users: {credential_error_msg}',
                    'timestamp': datetime.now().isoformat()
                }])
            if not scan_scope or 'rds' in services:
                _append_findings(session_id, [{
                    'type': 'RDS_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'resource': 'N/A',
                    'description': f'Unable to scan RDS instances: {credential_error_msg}',
                    'timestamp': datetime.now().isoformat()
                }])
            _update_session(session_id, status='failed', end_time=datetime.now().isoformat(), current_stage='Failed: No Credentials')
            return

        _update_session(session_id, current_stage='Initializing AWS service clients')
        s3 = boto3.client('s3', **client_kwargs)
        ec2 = boto3.client('ec2', **client_kwargs)
        iam = boto3.client('iam', **client_kwargs)
        rds = boto3.client('rds', **client_kwargs)

        def check_cancelled() -> bool:
            session = scan_sessions.get(session_id, {})
            return session.get('status') == 'cancelled'

        if not scan_scope or 's3' in services:
            if check_cancelled():
                _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                return
            _update_session(session_id, current_stage='Scanning S3 buckets')
            try:
                buckets = s3.list_buckets()
                for bucket in buckets.get('Buckets', []):
                    if check_cancelled():
                        _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                        return
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                        if any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                               for grant in acl.get('Grants', [])):
                            _append_findings(session_id, [{
                                'type': 'S3_PUBLIC_ACCESS',
                                'resource': bucket['Name'],
                                'severity': 'HIGH',
                                'description': 'S3 bucket is publicly accessible',
                                'timestamp': datetime.now().isoformat()
                            }])
                    except Exception as e:
                        _append_findings(session_id, [{
                            'type': 'S3_ACCESS_ERROR',
                            'resource': bucket['Name'],
                            'severity': 'MEDIUM',
                            'description': f'Unable to access bucket: {str(e)}',
                            'timestamp': datetime.now().isoformat()
                        }])
                    time.sleep(0.1)
            except Exception as e:
                _append_findings(session_id, [{
                    'type': 'S3_LIST_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to list S3 buckets: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }])
            step_index += 1
            _update_session(session_id, progress=int((step_index/total_steps)*100))

        if not scan_scope or 'ec2' in services:
            if check_cancelled():
                _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                return
            _update_session(session_id, current_stage='Scanning EC2 instances')
            try:
                instances = ec2.describe_instances()
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        if check_cancelled():
                            _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                            return
                        if instance.get('State', {}).get('Name') == 'running':
                            for sg in instance.get('SecurityGroups', []):
                                try:
                                    sg_rules = ec2.describe_security_group_rules(
                                        Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}]
                                    )
                                    for rule in sg_rules.get('SecurityGroupRules', []):
                                        if rule.get('IpProtocol') == '-1' and rule.get('CidrIpv4') == '0.0.0.0/0':
                                            _append_findings(session_id, [{
                                                'type': 'EC2_OPEN_SECURITY_GROUP',
                                                'resource': f"{instance.get('InstanceId')} ({sg.get('GroupName')})",
                                                'severity': 'HIGH',
                                                'description': 'EC2 instance has security group allowing all traffic',
                                                'timestamp': datetime.now().isoformat()
                                            }])
                                            break
                                except Exception:
                                    pass
                                time.sleep(0.05)
            except Exception as e:
                _append_findings(session_id, [{
                    'type': 'EC2_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan EC2 instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }])
            step_index += 1
            _update_session(session_id, progress=int((step_index/total_steps)*100))

        if not scan_scope or 'iam' in services:
            if check_cancelled():
                _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                return
            _update_session(session_id, current_stage='Scanning IAM users & policies')
            try:
                users = iam.list_users()
                for user in users.get('Users', []):
                    if check_cancelled():
                        _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                        return
                    try:
                        policies = iam.list_attached_user_policies(UserName=user['UserName'])
                        for policy in policies.get('AttachedPolicies', []):
                            if policy.get('PolicyName') in ['AdministratorAccess', 'PowerUserAccess']:
                                _append_findings(session_id, [{
                                    'type': 'IAM_OVERPRIVILEGED',
                                    'resource': user['UserName'],
                                    'severity': 'HIGH',
                                    'description': f"User has {policy.get('PolicyName')} policy attached",
                                    'timestamp': datetime.now().isoformat()
                                }])
                    except Exception:
                        pass
                    time.sleep(0.05)
            except Exception as e:
                _append_findings(session_id, [{
                    'type': 'IAM_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan IAM users: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }])
            step_index += 1
            _update_session(session_id, progress=int((step_index/total_steps)*100))

        if not scan_scope or 'rds' in services:
            if check_cancelled():
                _update_session(session_id, status='cancelled', end_time=datetime.now().isoformat())
                return
            _update_session(session_id, current_stage='Scanning RDS instances')
            try:
                instances = rds.describe_db_instances()
                for instance in instances.get('DBInstances', []):
                    if instance.get('PubliclyAccessible', False):
                        _append_findings(session_id, [{
                            'type': 'RDS_PUBLIC_ACCESS',
                            'resource': instance.get('DBInstanceIdentifier'),
                            'severity': 'HIGH',
                            'description': 'RDS instance is publicly accessible',
                            'timestamp': datetime.now().isoformat()
                        }])
                    time.sleep(0.05)
            except Exception as e:
                _append_findings(session_id, [{
                    'type': 'RDS_SCAN_ERROR',
                    'severity': 'MEDIUM',
                    'description': f'Unable to scan RDS instances: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }])
            step_index += 1
            _update_session(session_id, progress=int((step_index/total_steps)*100))

        _update_session(session_id, status='completed', end_time=datetime.now().isoformat(), current_stage='Completed', progress=100)
    except Exception as e:
        error_msg = str(e)
        existing_errors = [f for f in scan_sessions.get(session_id, {}).get('findings', []) if f.get('type') == 'CONNECTION_ERROR']
        if not existing_errors:
            _append_findings(session_id, [{
                'type': 'SCAN_ERROR',
                'severity': 'HIGH',
                'description': f'Unexpected error during scan: {error_msg}',
                'timestamp': datetime.now().isoformat()
            }])
        _update_session(session_id, status='failed', end_time=datetime.now().isoformat(), current_stage=f'Failed: {error_msg[:50]}')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/api/scan-aws', methods=['POST'])
def scan_aws():
    data = request.get_json()
    credentials_id = data.get('credentials', 'b67a60f0-32ec-4022-9bf8-26d0ade42a52')
    scan_scope = data.get('scope', [])

    if scan_scope:
        scope_set = set(scan_scope)
        if 'vpc' in scope_set:
            scope_set.add('ec2')
        scan_scope = list(scope_set)

    session_id = f"scan_{int(time.time())}"
    scan_sessions[session_id] = {
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'findings': [],
        'progress': 0,
        'current_stage': 'Initializing'
    }

    thread = threading.Thread(target=run_scan_session, args=(session_id, credentials_id, scan_scope, 'standard'), daemon=True)
    thread.start()

    return jsonify({
        'session_id': session_id,
        'timestamp': datetime.now().isoformat(),
        'message': 'Scan started',
        'credentials_used': credentials_id,
        'scan_scope': scan_scope
    })

@app.route('/api/scan-progress/<session_id>')
def scan_progress(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        return jsonify(session)
    else:
        return jsonify({'error': 'Session not found'}), 404


@app.route('/api/stop-scan/<session_id>', methods=['POST'])
def stop_scan(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        if session.get('status') == 'running':
            session['status'] = 'cancelled'
            session['end_time'] = datetime.now().isoformat()
            return jsonify({'message': 'Scan cancelled', 'session_id': session_id})
        return jsonify({'message': 'Scan not running', 'status': session.get('status')}), 400
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/scan-status')
def scan_status():
    active_scans = [s for s in scan_sessions.values() if s['status'] == 'running']
    completed_scans = [s for s in scan_sessions.values() if s['status'] == 'completed']
    
    return jsonify({
        'active_scans': len(active_scans),
        'completed_scans': len(completed_scans),
        'total_sessions': len(scan_sessions)
    })


@app.route('/api/sessions')
def list_sessions():
    sessions = []
    for session_id, session in scan_sessions.items():
        sessions.append({
            'id': session_id,
            'status': session.get('status'),
            'start_time': session.get('start_time'),
            'end_time': session.get('end_time'),
            'progress': session.get('progress', 0),
            'findings_count': len(session.get('findings', [])),
            'current_stage': session.get('current_stage', '')
        })
    try:
        sessions.sort(key=lambda s: s.get('start_time') or '', reverse=True)
    except Exception:
        pass
    return jsonify({'sessions': sessions, 'total_sessions': len(sessions)})


@app.route('/api/all-findings')
def all_findings():
    all_f = []
    for session in scan_sessions.values():
        all_f.extend(session.get('findings', []))
    summary = {
        'total': len(all_f),
        'high': len([f for f in all_f if f.get('severity') == 'HIGH']),
        'medium': len([f for f in all_f if f.get('severity') == 'MEDIUM']),
        'low': len([f for f in all_f if f.get('severity') == 'LOW'])
    }
    return jsonify({'findings': all_f, 'summary': summary, 'total_sessions': len(scan_sessions)})

@app.route('/api/latest-session')
def get_latest_session():
    if not scan_sessions:
        return jsonify({'error': 'No scan sessions found'}), 404

    latest_session_id = max(scan_sessions.keys(), key=lambda x: scan_sessions[x]['start_time'])
    latest_session = scan_sessions[latest_session_id]
    
    return jsonify({
        'session_id': latest_session_id,
        'session': latest_session
    })

@app.route('/api/findings/<session_id>')
def get_findings(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        return jsonify({
            'findings': session['findings'],
            'summary': {
                'total': len(session['findings']),
                'high': len([f for f in session['findings'] if f['severity'] == 'HIGH']),
                'medium': len([f for f in session['findings'] if f['severity'] == 'MEDIUM']),
                'low': len([f for f in session['findings'] if f['severity'] == 'LOW'])
            }
        })
    else:
        return jsonify({'error': 'Session not found'}), 404

@app.route('/api/download-report/<session_id>')
def download_report(session_id):
    if session_id in scan_sessions:
        session = scan_sessions[session_id]
        
        report = {
            'scan_session': session_id,
            'timestamp': session['start_time'],
            'duration': (datetime.fromisoformat(session['end_time']) - datetime.fromisoformat(session['start_time'])).total_seconds(),
            'findings': session['findings'],
            'summary': {
                'total': len(session['findings']),
                'high': len([f for f in session['findings'] if f['severity'] == 'HIGH']),
                'medium': len([f for f in session['findings'] if f['severity'] == 'MEDIUM']),
                'low': len([f for f in session['findings'] if f['severity'] == 'LOW'])
            }
        }
        
        return jsonify(report)
    else:
        return jsonify({'error': 'Session not found'}), 404

@app.route('/api/settings', methods=['GET', 'POST'])
def settings_api():
    if request.method == 'GET':
        has_credentials = False
        masked_access_key = None
        account_id = None
        
        try:
            sts_client = boto3.client('sts', region_name=settings_store.get('aws_region') or 'us-east-1')
            identity = sts_client.get_caller_identity()
            has_credentials = True
            account_id = identity.get('Account')
            
            access_key_id = settings_store.get('aws_access_key')
            if not access_key_id:
                access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
            
            if access_key_id:
                if len(access_key_id) > 8:
                    masked_access_key = f"{access_key_id[:4]}...{access_key_id[-4:]}"
                else:
                    masked_access_key = "****"
        except (NoCredentialsError, ClientError, Exception):
            has_credentials = False
        
        return jsonify({
            'aws_region': settings_store.get('aws_region') or 'us-east-1',
            'has_credentials': has_credentials,
            'masked_access_key': masked_access_key,
            'account_id': account_id
        })
    
    elif request.method == 'POST':
        data = request.get_json() or {}
        if 'aws_region' in data and data.get('aws_region'):
            settings_store['aws_region'] = data.get('aws_region') or 'us-east-1'

        return jsonify({'message': 'Settings saved successfully', 'timestamp': datetime.now().isoformat()})

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    data = request.get_json()
    
    access_key = (data or {}).get('aws_access_key') if data else None
    secret_key = (data or {}).get('aws_secret_key') if data else None
    region = (data or {}).get('aws_region') or settings_store.get('aws_region') or 'us-east-1'
    
    try:
        if access_key and secret_key:
            test_client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
        else:
            test_client = boto3.client('sts', region_name=region)
        
        response = test_client.get_caller_identity()
        
        return jsonify({
            'success': True,
            'message': 'AWS connection successful',
            'account_id': response.get('Account'),
            'user_arn': response.get('Arn'),
            'timestamp': datetime.now().isoformat()
        })
        
    except NoCredentialsError:
        return jsonify({'error': 'No AWS credentials found. Configure environment variables or AWS profile.'}), 401
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'SignatureDoesNotMatch' and 'Signature expired' in error_message:
            print(f"Warning: Neglecting time-related SignatureDoesNotMatch error for test-connection. Details: {e}")
            return jsonify({
                'success': True,
                'message': 'AWS connection successful (time synchronization warning observed, but credentials may be valid)',
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify({'error': f'AWS connection failed: {error_message} ({error_code})'}), 400
    except Exception as e:
        return jsonify({'error': f'Connection test failed: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)